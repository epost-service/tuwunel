#!/bin/bash
set -eo pipefail

BASEDIR=$(dirname "$0")

CI="${CI:-false}"
CI_VERBOSE="${CI_VERBOSE_ENV:-false}"
CI_VERBOSE_ENV="${CI_VERBOSE_ENV:-$CI_VERBOSE}"

default_cargo_profile="test"
default_feat_set="all"
default_rust_toolchain="nightly"
default_rust_target="x86_64-unknown-linux-gnu"
default_sys_name="debian"
default_sys_target="x86_64-v1-linux-gnu"
default_sys_version="testing-slim"

default_run=".*"
run="${1:-$default_run}"

skip=""
skip="TestPartialStateJoin.*"
skip="${skip}|TestRoomDeleteAlias/Pa.*/Can_delete_canonical_alias"
skip="${skip}|TestUnbanViaInvite.*"
skip="${skip}|TestToDeviceMessagesOverFederation/stopped_server"
skip="${skip}|TestLogin/parallel/POST_/login_as_non-existing_user_is_rejected"
skip="${skip}|TestThreadReceiptsInSyncMSC4102"
skip="${skip}|TestRoomCreate/Parallel/POST_/createRoom_makes_a_room_with_a_topic_and_writes_rich_topic_representation"
skip="${skip}|TestRoomCreate/Parallel/POST_/createRoom_makes_a_room_with_a_topic_via_initial_state_overwritten_by_topic"

set -a
cargo_profile="${cargo_profile:-$default_cargo_profile}"
feat_set="${feat_set:-$default_feat_set}"
rust_target="${rust_target:-$default_rust_target}"
rust_toolchain="${rust_toolchain:-$default_rust_toolchain}"
sys_name="${sys_name:-$default_sys_name}"
sys_target="${sys_target:-$default_sys_target}"
sys_version="${sys_version:-$default_sys_version}"

runner_name=$(echo $RUNNER_NAME | cut -d"." -f1)
runner_num=$(echo $RUNNER_NAME | cut -d"." -f2)
set +a

###############################################################################

envs=""
envs="$envs -e complement_verbose=${complement_verbose:-0}"
envs="$envs -e complement_count=${complement_count:-1}"
envs="$envs -e complement_parallel=${complement_parallel:-16}"
envs="$envs -e complement_shuffle=${complement_shuffle:-0}"
envs="$envs -e complement_timeout=${complement_timeout:-1h}"
envs="$envs -e complement_skip=${complement_skip:-$skip}"
envs="$envs -e complement_run=${run}"

set -x
tester_image="complement-tester--${sys_name}--${sys_version}--${sys_target}"
testee_image="complement-testee--${cargo_profile}--${rust_toolchain}--${rust_target}--${feat_set}--${sys_name}--${sys_version}--${sys_target}"
name="complement_tester__${sys_name}__${sys_version}__${sys_target}"
sock="/var/run/docker.sock"
arg="--name $name -v $sock:$sock --network=host $envs $tester_image ${testee_image}"
set +x

if test "$CI_VERBOSE_ENV" = "true"; then
	date
	env
fi

docker rm -f "$name" 2>/dev/null

arg="-d $arg"
cid=$(docker run $arg)

if test "$CI" = "true"; then
	echo -n "$cid" > "$name"
fi

output_src="$cid:/usr/src/complement/full_output.jsonl"
output_dst="complement.jsonl"
extract_output() {
	docker cp "$output_src" "$output_dst"
}

result_src="$cid:/usr/src/complement/new_results.jsonl"
result_dst="tests/test_results/complement/test_results.jsonl"
extract_results() {
	docker cp "$result_src" "$result_dst"
}

trap 'extract_output; set +x; date; echo -e "\033[1;41;37mERROR\033[0m"' ERR
trap 'docker container stop $cid; extract_output' INT
docker logs -f "$cid"
docker wait "$cid" 2>/dev/null

extract_results
git diff -U0 --color --shortstat "$result_dst" | (grep "$run" || true)

git diff --quiet --exit-code "$result_dst"
echo -e "\033[1;42;30mACCEPT\033[0m"
