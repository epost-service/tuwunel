#[cfg(tuwunel_bench)]
extern crate test;

use std::{
	borrow::Borrow,
	collections::{HashMap, HashSet},
	sync::atomic::{AtomicU64, Ordering::SeqCst},
};

use futures::{future, future::ready};
use maplit::{btreemap, hashmap, hashset};
use ruma::{
	EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, RoomId, RoomVersionId, Signatures, UserId,
	events::{
		StateEventType, TimelineEventType,
		room::{
			join_rules::{JoinRule, RoomJoinRulesEventContent},
			member::{MembershipState, RoomMemberEventContent},
		},
	},
	int, room_id, uint, user_id,
};
use serde_json::{
	json,
	value::{RawValue as RawJsonValue, to_raw_value as to_raw_json_value},
};

use crate::{
	matrix::{Event, Pdu, pdu::EventHash},
	state_res::{self as state_res, Error, Result, StateMap},
};

static SERVER_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

#[cfg(tuwunel_bench)]
#[cfg_attr(tuwunel_bench, bench)]
fn lexico_topo_sort(c: &mut test::Bencher) {
	let graph = hashmap! {
		event_id("l") => hashset![event_id("o")],
		event_id("m") => hashset![event_id("n"), event_id("o")],
		event_id("n") => hashset![event_id("o")],
		event_id("o") => hashset![], // "o" has zero outgoing edges but 4 incoming edges
		event_id("p") => hashset![event_id("o")],
	};

	c.iter(|| {
		let _ = state_res::lexicographical_topological_sort(&graph, &|_| {
			future::ok((int!(0), MilliSecondsSinceUnixEpoch(uint!(0))))
		});
	});
}

#[cfg(tuwunel_bench)]
#[cfg_attr(tuwunel_bench, bench)]
fn resolution_shallow_auth_chain(c: &mut test::Bencher) {
	let mut store = TestStore(hashmap! {});

	// build up the DAG
	let (state_at_bob, state_at_charlie, _) = store.set_up();

	c.iter(|| async {
		let ev_map = store.0.clone();
		let state_sets = [&state_at_bob, &state_at_charlie];
		let fetch = |id: OwnedEventId| ready(ev_map.get(&id).map(ToOwned::to_owned));
		let exists = |id: OwnedEventId| ready(ev_map.get(&id).is_some());
		let auth_chain_sets: Vec<HashSet<_>> = state_sets
			.iter()
			.map(|map| {
				store
					.auth_event_ids(room_id(), map.values().cloned().collect())
					.unwrap()
			})
			.collect();

		let _ = match state_res::resolve(
			&RoomVersionId::V6,
			state_sets.into_iter(),
			&auth_chain_sets,
			&fetch,
			&exists,
		)
		.await
		{
			| Ok(state) => state,
			| Err(e) => panic!("{e}"),
		};
	});
}

#[cfg(tuwunel_bench)]
#[cfg_attr(tuwunel_bench, bench)]
fn resolve_deeper_event_set(c: &mut test::Bencher) {
	let mut inner = INITIAL_EVENTS();
	let ban = BAN_STATE_SET();

	inner.extend(ban);
	let store = TestStore(inner.clone());

	let state_set_a = [
		inner.get(&event_id("CREATE")).unwrap(),
		inner.get(&event_id("IJR")).unwrap(),
		inner.get(&event_id("IMA")).unwrap(),
		inner.get(&event_id("IMB")).unwrap(),
		inner.get(&event_id("IMC")).unwrap(),
		inner.get(&event_id("MB")).unwrap(),
		inner.get(&event_id("PA")).unwrap(),
	]
	.iter()
	.map(|ev| {
		(
			(ev.event_type().clone().into(), ev.state_key().unwrap().into()),
			ev.event_id().to_owned(),
		)
	})
	.collect::<StateMap<_>>();

	let state_set_b = [
		inner.get(&event_id("CREATE")).unwrap(),
		inner.get(&event_id("IJR")).unwrap(),
		inner.get(&event_id("IMA")).unwrap(),
		inner.get(&event_id("IMB")).unwrap(),
		inner.get(&event_id("IMC")).unwrap(),
		inner.get(&event_id("IME")).unwrap(),
		inner.get(&event_id("PA")).unwrap(),
	]
	.iter()
	.map(|ev| {
		(
			(ev.event_type().clone().into(), ev.state_key().unwrap().into()),
			ev.event_id().to_owned(),
		)
	})
	.collect::<StateMap<_>>();

	c.iter(|| async {
		let state_sets = [&state_set_a, &state_set_b];
		let auth_chain_sets: Vec<HashSet<_>> = state_sets
			.iter()
			.map(|map| {
				store
					.auth_event_ids(room_id(), map.values().cloned().collect())
					.unwrap()
			})
			.collect();

		let fetch = |id: OwnedEventId| ready(inner.get(&id).map(ToOwned::to_owned));
		let exists = |id: OwnedEventId| ready(inner.get(&id).is_some());
		let _ = match state_res::resolve(
			&RoomVersionId::V6,
			state_sets.into_iter(),
			&auth_chain_sets,
			&fetch,
			&exists,
		)
		.await
		{
			| Ok(state) => state,
			| Err(_) => panic!("resolution failed during benchmarking"),
		};
	});
}

//*/////////////////////////////////////////////////////////////////////
//
//  IMPLEMENTATION DETAILS AHEAD
//
/////////////////////////////////////////////////////////////////////*/
struct TestStore<E: Event>(HashMap<OwnedEventId, E>);

#[allow(unused)]
impl<E: Event + Clone> TestStore<E> {
	fn get_event(&self, room_id: &RoomId, event_id: &EventId) -> Result<E> {
		self.0
			.get(event_id)
			.cloned()
			.ok_or_else(|| Error::NotFound(format!("{} not found", event_id)))
	}

	/// Returns the events that correspond to the `event_ids` sorted in the same
	/// order.
	fn get_events(&self, room_id: &RoomId, event_ids: &[OwnedEventId]) -> Result<Vec<E>> {
		let mut events = vec![];
		for id in event_ids {
			events.push(self.get_event(room_id, id)?);
		}
		Ok(events)
	}

	/// Returns a Vec of the related auth events to the given `event`.
	fn auth_event_ids(
		&self,
		room_id: &RoomId,
		event_ids: Vec<OwnedEventId>,
	) -> Result<HashSet<OwnedEventId>> {
		let mut result = HashSet::new();
		let mut stack = event_ids;

		// DFS for auth event chain
		while !stack.is_empty() {
			let ev_id = stack.pop().unwrap();
			if result.contains(&ev_id) {
				continue;
			}

			result.insert(ev_id.clone());

			let event = self.get_event(room_id, ev_id.borrow())?;

			stack.extend(event.auth_events().map(ToOwned::to_owned));
		}

		Ok(result)
	}

	/// Returns a vector representing the difference in auth chains of the given
	/// `events`.
	fn auth_chain_diff(
		&self,
		room_id: &RoomId,
		event_ids: Vec<Vec<OwnedEventId>>,
	) -> Result<Vec<OwnedEventId>> {
		let mut auth_chain_sets = vec![];
		for ids in event_ids {
			// TODO state store `auth_event_ids` returns self in the event ids list
			// when an event returns `auth_event_ids` self is not contained
			let chain = self
				.auth_event_ids(room_id, ids)?
				.into_iter()
				.collect::<HashSet<_>>();
			auth_chain_sets.push(chain);
		}

		if let Some(first) = auth_chain_sets.first().cloned() {
			let common = auth_chain_sets
				.iter()
				.skip(1)
				.fold(first, |a, b| a.intersection(b).cloned().collect::<HashSet<_>>());

			Ok(auth_chain_sets
				.into_iter()
				.flatten()
				.filter(|id| !common.contains(id))
				.collect())
		} else {
			Ok(vec![])
		}
	}
}

impl TestStore<Pdu> {
	#[allow(clippy::type_complexity)]
	fn set_up(
		&mut self,
	) -> (StateMap<OwnedEventId>, StateMap<OwnedEventId>, StateMap<OwnedEventId>) {
		let create_event = to_pdu_event::<&EventId>(
			"CREATE",
			alice(),
			TimelineEventType::RoomCreate,
			Some(""),
			to_raw_json_value(&json!({ "creator": alice() })).unwrap(),
			&[],
			&[],
		);
		let cre = create_event.event_id().to_owned();
		self.0.insert(cre.clone(), create_event.clone());

		let alice_mem = to_pdu_event(
			"IMA",
			alice(),
			TimelineEventType::RoomMember,
			Some(alice().to_string().as_str()),
			member_content_join(),
			&[cre.clone()],
			&[cre.clone()],
		);
		self.0
			.insert(alice_mem.event_id().to_owned(), alice_mem.clone());

		let join_rules = to_pdu_event(
			"IJR",
			alice(),
			TimelineEventType::RoomJoinRules,
			Some(""),
			to_raw_json_value(&RoomJoinRulesEventContent::new(JoinRule::Public)).unwrap(),
			&[cre.clone(), alice_mem.event_id().to_owned()],
			&[alice_mem.event_id().to_owned()],
		);
		self.0
			.insert(join_rules.event_id().to_owned(), join_rules.clone());

		// Bob and Charlie join at the same time, so there is a fork
		// this will be represented in the state_sets when we resolve
		let bob_mem = to_pdu_event(
			"IMB",
			bob(),
			TimelineEventType::RoomMember,
			Some(bob().to_string().as_str()),
			member_content_join(),
			&[cre.clone(), join_rules.event_id().to_owned()],
			&[join_rules.event_id().to_owned()],
		);
		self.0
			.insert(bob_mem.event_id().to_owned(), bob_mem.clone());

		let charlie_mem = to_pdu_event(
			"IMC",
			charlie(),
			TimelineEventType::RoomMember,
			Some(charlie().to_string().as_str()),
			member_content_join(),
			&[cre, join_rules.event_id().to_owned()],
			&[join_rules.event_id().to_owned()],
		);
		self.0
			.insert(charlie_mem.event_id().to_owned(), charlie_mem.clone());

		let state_at_bob = [&create_event, &alice_mem, &join_rules, &bob_mem]
			.iter()
			.map(|ev| {
				(
					(ev.event_type().clone().into(), ev.state_key().unwrap().into()),
					ev.event_id().to_owned(),
				)
			})
			.collect::<StateMap<_>>();

		let state_at_charlie = [&create_event, &alice_mem, &join_rules, &charlie_mem]
			.iter()
			.map(|ev| {
				(
					(ev.event_type().clone().into(), ev.state_key().unwrap().into()),
					ev.event_id().to_owned(),
				)
			})
			.collect::<StateMap<_>>();

		let expected = [&create_event, &alice_mem, &join_rules, &bob_mem, &charlie_mem]
			.iter()
			.map(|ev| {
				(
					(ev.event_type().clone().into(), ev.state_key().unwrap().into()),
					ev.event_id().to_owned(),
				)
			})
			.collect::<StateMap<_>>();

		(state_at_bob, state_at_charlie, expected)
	}
}

fn event_id(id: &str) -> OwnedEventId {
	if id.contains('$') {
		return id.try_into().unwrap();
	}
	format!("${}:foo", id).try_into().unwrap()
}

fn alice() -> &'static UserId { user_id!("@alice:foo") }

fn bob() -> &'static UserId { user_id!("@bob:foo") }

fn charlie() -> &'static UserId { user_id!("@charlie:foo") }

fn ella() -> &'static UserId { user_id!("@ella:foo") }

fn room_id() -> &'static RoomId { room_id!("!test:foo") }

fn member_content_ban() -> Box<RawJsonValue> {
	to_raw_json_value(&RoomMemberEventContent::new(MembershipState::Ban)).unwrap()
}

fn member_content_join() -> Box<RawJsonValue> {
	to_raw_json_value(&RoomMemberEventContent::new(MembershipState::Join)).unwrap()
}

fn to_pdu_event<S>(
	id: &str,
	sender: &UserId,
	ev_type: TimelineEventType,
	state_key: Option<&str>,
	content: Box<RawJsonValue>,
	auth_events: &[S],
	prev_events: &[S],
) -> Pdu
where
	S: AsRef<str>,
{
	// We don't care if the addition happens in order just that it is atomic
	// (each event has its own value)
	let ts = SERVER_TIMESTAMP.fetch_add(1, SeqCst);
	let id = if id.contains('$') {
		id.to_owned()
	} else {
		format!("${}:foo", id)
	};
	let auth_events = auth_events
		.iter()
		.map(AsRef::as_ref)
		.map(event_id)
		.collect::<Vec<_>>();
	let prev_events = prev_events
		.iter()
		.map(AsRef::as_ref)
		.map(event_id)
		.collect::<Vec<_>>();

	Pdu {
		event_id: id.try_into().unwrap(),
		room_id: room_id().to_owned(),
		sender: sender.to_owned(),
		origin_server_ts: ts.try_into().unwrap(),
		state_key: state_key.map(Into::into),
		kind: ev_type,
		content,
		origin: None,
		redacts: None,
		unsigned: None,
		auth_events,
		prev_events,
		depth: uint!(0),
		hashes: EventHash::default(),
		signatures: None,
	}
}

// all graphs start with these input events
#[allow(non_snake_case)]
fn INITIAL_EVENTS() -> HashMap<OwnedEventId, Pdu> {
	vec![
		to_pdu_event::<&EventId>(
			"CREATE",
			alice(),
			TimelineEventType::RoomCreate,
			Some(""),
			to_raw_json_value(&json!({ "creator": alice() })).unwrap(),
			&[],
			&[],
		),
		to_pdu_event(
			"IMA",
			alice(),
			TimelineEventType::RoomMember,
			Some(alice().as_str()),
			member_content_join(),
			&["CREATE"],
			&["CREATE"],
		),
		to_pdu_event(
			"IPOWER",
			alice(),
			TimelineEventType::RoomPowerLevels,
			Some(""),
			to_raw_json_value(&json!({ "users": { alice(): 100 } })).unwrap(),
			&["CREATE", "IMA"],
			&["IMA"],
		),
		to_pdu_event(
			"IJR",
			alice(),
			TimelineEventType::RoomJoinRules,
			Some(""),
			to_raw_json_value(&RoomJoinRulesEventContent::new(JoinRule::Public)).unwrap(),
			&["CREATE", "IMA", "IPOWER"],
			&["IPOWER"],
		),
		to_pdu_event(
			"IMB",
			bob(),
			TimelineEventType::RoomMember,
			Some(bob().to_string().as_str()),
			member_content_join(),
			&["CREATE", "IJR", "IPOWER"],
			&["IJR"],
		),
		to_pdu_event(
			"IMC",
			charlie(),
			TimelineEventType::RoomMember,
			Some(charlie().to_string().as_str()),
			member_content_join(),
			&["CREATE", "IJR", "IPOWER"],
			&["IMB"],
		),
		to_pdu_event::<&EventId>(
			"START",
			charlie(),
			TimelineEventType::RoomTopic,
			Some(""),
			to_raw_json_value(&json!({})).unwrap(),
			&[],
			&[],
		),
		to_pdu_event::<&EventId>(
			"END",
			charlie(),
			TimelineEventType::RoomTopic,
			Some(""),
			to_raw_json_value(&json!({})).unwrap(),
			&[],
			&[],
		),
	]
	.into_iter()
	.map(|ev| (ev.event_id().to_owned(), ev))
	.collect()
}

// all graphs start with these input events
#[allow(non_snake_case)]
fn BAN_STATE_SET() -> HashMap<OwnedEventId, Pdu> {
	vec![
		to_pdu_event(
			"PA",
			alice(),
			TimelineEventType::RoomPowerLevels,
			Some(""),
			to_raw_json_value(&json!({ "users": { alice(): 100, bob(): 50 } })).unwrap(),
			&["CREATE", "IMA", "IPOWER"], // auth_events
			&["START"],                   // prev_events
		),
		to_pdu_event(
			"PB",
			alice(),
			TimelineEventType::RoomPowerLevels,
			Some(""),
			to_raw_json_value(&json!({ "users": { alice(): 100, bob(): 50 } })).unwrap(),
			&["CREATE", "IMA", "IPOWER"],
			&["END"],
		),
		to_pdu_event(
			"MB",
			alice(),
			TimelineEventType::RoomMember,
			Some(ella().as_str()),
			member_content_ban(),
			&["CREATE", "IMA", "PB"],
			&["PA"],
		),
		to_pdu_event(
			"IME",
			ella(),
			TimelineEventType::RoomMember,
			Some(ella().as_str()),
			member_content_join(),
			&["CREATE", "IJR", "PA"],
			&["MB"],
		),
	]
	.into_iter()
	.map(|ev| (ev.event_id().to_owned(), ev))
	.collect()
}
