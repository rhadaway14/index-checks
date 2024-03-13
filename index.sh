#!/usr/bin/env bash

version="1.0.1"

_usage() {
  echo -n "${__script} [OPTION]...

 This will export all of the indexes and their metrics over a given time period for one or more clusters using the proxied prometheus
 endpoints in Couchbase Server 7.0+.  More information about these capabilities and metric descriptions can be found in the docs:

 - https://docs.couchbase.com/server/current/rest-api/rest-statistics-multiple.html
 - https://docs.couchbase.com/server/current/metrics-reference/metrics-reference.html

 Metrics will be aggregated by sum or avg depending on the metric.  The context of these metrics is that they are the sum total from
 the start value to present, if it is averaged this is the interpreted as the average value within time range the given step.  A
 lower step value yields more precision as there are more samples, which is a larger payload and more work to process per metric.  The
 following metrics are summed, every other metric is averaged:

   - index_num_docs_pending_and_queued
   - index_num_docs_indexed
   - index_num_requests
   - index_cache_hits
   - index_cache_misses

 Common Ranges:
  minute: (6 samples)
    start: -60
    step: 10
  hour: (60 samples)
    start: -3600
    step: 60
  12hour: (12 samples)
    start: -43200
    step: 3600
  day: (24 samples)
    start: -86400
    step: 3600
  week: (7 samples)
    start: -604800
    step: 86400

 Options:
  -c, --cluster(s)        A comma-delimited list of one or more clusters to retrieve the slow queries from.  (default: localhost)
  -u, --username          Cluster Admin or RBAC username (default: Administrator)
  -p, --password          Cluster Admin or RBAC password (default: password)
  -s, --start             (optional) The point at which the gathering of metrics commences, specified in seconds as a negative integer. The
                          negative integer-value is added to the current time when execution occurs, so as to derive a historic
                          timestamp. Metrics are then gathered for the time-period that starts at the historic timestamp. (default: -86400)
  -e, --step              (optional) The length of the interval that occurs between each statistic-retrieval during the time-period that
                          commences with start and concludes with end, specified as a positive integer. (default: 3600)
  -b, --buckets           (optional) A comma-delimited list of buckets to filter on (default:*)
  -i, --include-replicas  (optional) Whether or not to include the replica indexes (default: false)
  -r, --port              (optional) The port to use (default: 8091)
  -l, --protocol          (optional) The protocol to use (default: http)
  -t, --timeout           (optional) The timeout to use for HTTP requests (default: 5)
  -o, --output-dir        (optional) The name of the output directory to use if output is csv (default: pwd)
  -f, --output-file       (optional) The name of the output file if output is csv (default: index-usage-yyyy-mm-dd-HMS.csv)
  --log-level             The log level to to use 0-7 (default: 6)
  --debug                 Shortcut for --log-level 7
  --help                  Display this help and exit
  --version               Output version information and exit
"
}

# default variables / flags and their optional corresponding environment variables used in the script
CLUSTERS=${CLUSTERS:-'localhost'}
USERNAME=${CB_USERNAME:-'Administrator'}
PASSWORD=${CB_PASSWORD:-'password'}
BUCKETS=${BUCKETS:-'*'}
PORT=${PORT:-'8091'}
START=${START:-'-86400'}
STEP=${STEP:-'3600'}
PROTOCOL=${PROTOCOL:-'http'}
TIMEOUT=${TIMEOUT:-5}
INCLUDE_REPLICAS=${INCLUDE_REPLICAS:-false}
OUTPUT_DIR=${OUTPUT_DIR:-$(pwd)}
OUTPUT_FILE=${OUTPUT_FILE:-"index-export-$(date +"%Y-%m-%d-%H%M%S").csv"}

# _options
# -----------------------------------
# Parses CLI options
# -----------------------------------
_options() {
  debug ""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c|--cluster|--clusters) CLUSTERS=${2} && shift 2;;
      -r|--port) PORT=${2} && shift 2;;
      -l|--protocol) PROTOCOL=${2} && shift 2;;
      -b|--buckets) BUCKETS=${2} && shift 2;;
      -t|--timeout) TIMEOUT=${2} && shift 2;;
      -i|--include-replicas) INCLUDE_REPLICAS=${2} && shift 2;;
      -s|--start) START=${2} && shift 2;;
      -e|--step) STEP=${2} && shift 2;;
      -u|--username) USERNAME=${2} && shift 2;;
      -o|--output-dir) OUTPUT_DIR=${2} && shift 2;;
      -f|--output-file) OUTPUT_FILE=${2} && shift 2;;
      -p|--password)
        # if no password was specified prompt for one
        if [ -z "${2:-}" ] || [[ "${2}" == --* ]]; then
          stty -echo # disable keyboard input
          read -p "Password: " -r PASSWORD # prompt the user for the password
          stty echo # enable keyboard input
          echo # new line
          tput cuu1 && tput el # clear the previous line
          shift
        else
          PASSWORD="${2}" # set the passed password
          shift 2
        fi
        ;;
      *)
        error "invalid option: '$1'."
        exit 1
        ;;
    esac
  done
}

# _dependencies
# -----------------------------------
# Ensure script dependencies exist
# -----------------------------------
_dependencies() {
  debug ""
  # check if jq is installed
  if [ "$(command -v jq)" = "" ]; then
    emergency "jq command is required, see (https://stedolan.github.io/jq/download)"
  fi
}

# validate
# -----------------------------------
# Validate Params
# -----------------------------------
_validate() {
  debug ""
  local valid=true
  # validate the cluster argument does not contain any port references
  if [[ "$CLUSTERS" =~ :[0-9]+ ]]; then
    warning "Do not specifiy the port for the hostnames in the -c/--clusters argument" && valid=false
  fi
  # validate the cluster argument does not contain the protocol
  if [[ "$CLUSTERS" =~ https?:// ]]; then
    warning "Do not specifiy the protocol (http/https) for the hostnames in the -c/--clusters argument" && valid=false
  fi
  # validate that there is a username
  if [[ -z "$USERNAME" ]]; then
    warning "The -u/--username argument is required" && valid=false
  fi
  # validate that there is a password
  if [[ -z "$PASSWORD" ]]; then
    warning "The -p/--password argument is required" && valid=false
  fi
  # validate the protocol argument is http/https
  if ! [[ "$PROTOCOL" =~ ^https?$ ]]; then
    warning "The -s/--protocol argument can only be \"http\" or \"https\"" && valid=false
  fi
  # validate the port argument is a number
  if ! [[ "$PORT" =~ ^[1-9][0-9]*$ ]]; then
    warning "The -r/--port argument must be an integer greater than 0" && valid=false
  fi
  # validate the timeout argument is a number
  if ! [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    warning "The -t/--timeout argument must be an integer greater than 0" && valid=false
  fi
  # validate the log level is between 0-7 argument is a number
  if ! [[ "$LOG_LEVEL" =~ ^[0-7]$ ]]; then
    warning "The -l/--log-level argument must be an integer between 0-7" && valid=false
  fi
  # validate the include replicas argument is a boolean
  if ! [[ "$INCLUDE_REPLICAS" =~ ^(true|false)$ ]]; then
    warning "The -i/--include-replicas argument can only be \"true\" or \"false\"" && valid=false
  fi
  # validate the start argument is a number
  if ! [[ "$START" =~ ^-[1-9][0-9]*$ ]]; then
    warning "The -s/--start argument must be an integer less than 0" && valid=false
  fi
  # validate the port argument is a number
  if ! [[ "$STEP" =~ ^[1-9][0-9]*$ ]]; then
    warning "The -e/--step argument must be an integer greater than 0" && valid=false
  fi
  # if there are errors
  if ( ! $valid ); then
    exit 1
  fi
}

# main
# -----------------------------------
# Main function
# -----------------------------------
main() {
  # log the invocation command and arguments
  debug "
  invocation:
    $__invocation
  arguments:
    clusters: $CLUSTERS
    username: $USERNAME
    password: ********
    buckets: $BUCKETS
    include_replicas: $INCLUDE_REPLICAS
    port: $PORT
    protocol: $PROTOCOL
    timeout: $TIMEOUT
    output_dir: $OUTPUT_DIR
    output_file: $OUTPUT_FILE"

  # loop over each of the clusters and get all of the indexes
  for cluster in $(echo "$CLUSTERS" | jq --slurp --raw-output --raw-input 'split(",") | .[]')
  do
    # local variable to hold the name of the cluster
    local cluster_name
    cluster_name=$(getClusterName "$cluster")
    if [ "$LOG_LEVEL" != "7" ]; then
      echo -en "\r\033[KCluster: $cluster_name"
    fi
    local indexes="" # local variable to hold all of the indexes
    # get the indexes for the cluster
    indexes="$(getClusterIndexes "$cluster")"

    # counters to hold progress
    local counter=0
    local index_count
    index_count=$(echo "$indexes" | jq -r -c '. | length')

    # loop over each one of the indexes
    for row in $(echo "${indexes}" | jq -r '.[] | @base64'); do
      # local function to parse each row
      _jq() {
       echo "${row}" | base64 --decode | jq -r "${1}"
      }
      local index
      local bucket
      local scope
      local collection
      local definition
      local metrics
      # get each value from the row
      hosts=$(_jq '.hosts | join(",")')
      index=$(_jq '.index')
      bucket=$(_jq '.bucket')
      scope=$(_jq '.scope')
      collection=$(_jq '.collection')
      definition=$(_jq '.definition')

      # increment the counter
      counter=$((counter+1))
      # output what is currently being worked on
      if [ "$LOG_LEVEL" != "7" ]; then
        echo -en "\r\033[K($counter/$index_count) || Cluster: $cluster_name || Bucket: $bucket  || Scope: $scope || Collection: $collection || Index: $index"
      fi
      # get the metrics
      metrics="$(getIndexMetrics "$cluster" "$bucket" "$scope" "$collection" "$index" "$START" "$STEP")"

      # write the results out to the file
      writeOutput "$cluster_name" "$bucket" "$scope" "$collection" "$index" "$hosts" "$definition" "$metrics" "$OUTPUT_DIR/$OUTPUT_FILE"
    done
  done

  if [ "$LOG_LEVEL" != "7" ]; then
    echo -en "\r\033[K"
  fi
  echo "Results saved to: $OUTPUT_DIR/$OUTPUT_FILE"
}

# writeOutput
# -----------------------------------
# Retrieves the metrics for a specific index
# -----------------------------------
# shellcheck disable=SC2001
writeOutput() {
  local cluster_name="${1}"
  local bucket="${2}"
  local scope="${3}"
  local collection="${4}"
  local index="${5}"
  local hosts="${6}"
  local definition="${7}"
  local metrics="${8}"
  local file="${9}"

  debug "
    cluster_name: $cluster_name
    bucket: $bucket
    scope: $scope
    collection: $collection
    index: $index
    hosts: $hosts
    definition: $definition
    metrics: $metrics
    file: $file"

  # check to see if the file exists already, if not create it and set the headings based on the first record passed
  if [ ! -f "$file" ]; then
    # create the headings
    local headings
    headings=$(jq -n -r -c \
      --argjson metrics "$metrics" \
      --argjson headings '["cluster_name","bucket","scope","collection","index","hosts","definition"]' \
      '$headings + [$metrics | .[].name] | join(",")')
    # write the headings to the fiile
    echo "$headings" > "$file"
  fi

  # write the output record in csv format
  local record
  record=$(jq -n -r -c \
    --arg cluster_name "$cluster_name" \
    --arg bucket "$bucket" \
    --arg scope "$scope" \
    --arg collection "$collection" \
    --arg index "$index" \
    --arg hosts "$hosts" \
    --arg definition "$definition" \
    --argjson metrics "$metrics" \
    '(
      [$cluster_name,$bucket,$scope,$collection,$index,$hosts,$definition]
      +
      [$metrics | .[].value]
    ) | @csv')
  echo "$record" >> "$file"
}

# getIndexMetrics
# -----------------------------------
# Retrieves the metrics for a specific index
# -----------------------------------
# shellcheck disable=SC2001
getIndexMetrics() {
  local cluster="${1}"
  local bucket="${2}"
  local scope="${3}"
  local collection="${4}"
  local index="${5}"
  local start="${6}"
  local step="${7}"
  debug "
    cluster: $cluster
    bucket: $bucket
    scope: $scope
    collection: $collection
    index: $index
    start: $start
    step: $step"
  # call the index status api
  local url="$PROTOCOL://$cluster:$PORT/pools/default/stats/range/"
  debug "url: $url"
  local irate_metrics="index_num_docs_indexed|index_avg_scan_latency|index_num_requests|index_num_rows_returned|index_num_rows_scanned|index_scan_bytes_read|index_cache_hits|index_cache_misses|index_total_scan_duration"
  # first metric set is all instance="index" metrics for the bucket, scope, collection that are not irate metrics
  # second metric set is only the irate metrics with the irate function applied
  # third metric set is the # of items in the collection
  local payload="[{
    \"step\": $step,
    \"start\": $start,
    \"metric\": [
      { \"label\": \"instance\", \"value\": \"index\" },
      { \"label\": \"bucket\", \"value\": \"$bucket\" },
      { \"label\": \"scope\", \"value\": \"$scope\" },
      { \"label\": \"collection\", \"value\": \"$collection\" },
      { \"label\": \"index\", \"value\": \"$index\" },
      { \"label\": \"name\", \"operator\": \"!~\", \"value\": \"$irate_metrics\" }
    ],
    \"alignTimestamps\": true
  }, {
    \"step\": $step,
    \"start\": $start,
    \"metric\": [
      { \"label\": \"instance\", \"value\": \"index\" },
      { \"label\": \"bucket\", \"value\": \"$bucket\" },
      { \"label\": \"scope\", \"value\": \"$scope\" },
      { \"label\": \"collection\", \"value\": \"$collection\" },
      { \"label\": \"index\", \"value\": \"$index\" },
      { \"label\": \"name\", \"operator\": \"=~\", \"value\": \"$irate_metrics\" }
    ],
    \"applyFunctions\": [\"irate\"],
    \"alignTimestamps\": true
  }, {
    \"step\": $step,
    \"start\": $start,
    \"metric\": [
      { \"label\": \"instance\", \"value\": \"kv\" },
      { \"label\": \"bucket\", \"value\": \"$bucket\" },
      { \"label\": \"scope\", \"value\": \"$scope\" },
      { \"label\": \"collection\", \"value\": \"$collection\" },
      { \"label\": \"name\", \"value\": \"kv_collection_item_count\" }
    ],
    \"nodesAggregation\": \"sum\",
    \"alignTimestamps\": true
  }]"
  local http_response
  http_response=$(curl -k\
    --user "$USERNAME:$PASSWORD" \
    --silent \
    --connect-timeout "$TIMEOUT" \
    --request POST \
    -d "$payload" \
    --write-out "HTTPSTATUS:%{http_code}" \
    "$url")
  local http_body
  http_body=$(echo "$http_response" | sed -e 's/HTTPSTATUS\:.*//g')
  local http_status
  http_status=$(echo "$http_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
  # inspect the response code
  if [ "$http_status" -eq "200" ]; then
    echo "$http_body" | jq -r -c '[
      # loop over each of the data responses
      .[].data[] |
      # save the metric name as a variable
      .metric.name as $name |
      . |
      # build a name/value object for each metrics
      {
        "name": (
          # clean up some of the metric names to make more sense
          if (["index_scan_bytes_read","index_num_rows_returned","index_num_rows_scanned"] | index($name)) then
            $name | sub("index_";"index_avg_")
          elif (["index_num_requests","index_num_docs_queued","index_num_docs_indexed","index_num_docs_pending_and_queued"] | index($name)) then
            $name | sub("index_";"index_total_")
          else
            $name
          end
        ),
        # comment the line below to see the sample returned
        #"values": (.values | map(.[1] | tonumber)),
        "value": (
          # if the metric is in the list it should be an summed otherwise average it
          if (["index_num_docs_pending_and_queued","index_num_docs_indexed","index_num_requests","index_cache_hits","index_cache_misses"] | index($name)) then
            (.values | map(.[1] | tonumber)) | add | tostring
          else
            (.values | map(.[1] | tonumber)) | add / length | tostring
          end
          )
      }
    ] |
    # save the current metrics array as a variable
    . as $metrics |
    # add the current metrics array to a new array which will derive index_selectivity
    $metrics +
    [
      # reduce the current metrics array to an object with the keys of index_items_count and kv_collection_item_count
      reduce $metrics[] as $item (
        {};
        if (["index_items_count","kv_collection_item_count"] | index($item.name)) then
          .[$item.name] = ($item.value | tonumber)
        else
          .
        end
      ) |
      # add a new index_selectivity metric by dividing the index_items_count by kv_collection_item_count
      {
        "name": "index_selectivity",
        "value": (
          if (.kv_collection_item_count > 0) then
            ((.index_items_count / .kv_collection_item_count) * 100)
          else
            0
          end | tostring
        )
      }
    ] | sort_by(.name)'
  else
    debug "http_status: $http_status"
    debug "http_body: $http_body"
    error "Unable to reach the cluster: ${cluster} at ${url}"
    exit 1
  fi
}

# getClusterIndexes
# -----------------------------------
# Retrieves the indexes for a cluster
# -----------------------------------
# shellcheck disable=SC2001
getClusterIndexes() {
  local cluster="${1}"
  debug "cluster: $cluster"
  # call the index status api
  local url="$PROTOCOL://$cluster:$PORT/indexStatus"
  debug "url: $url"
  local http_response
  http_response=$(curl -k \
    --user "$USERNAME:$PASSWORD" \
    --silent \
    --connect-timeout "$TIMEOUT" \
    --request GET \
    --write-out "HTTPSTATUS:%{http_code}" \
    "$url")
  local http_body
  http_body=$(echo "$http_response" | sed -e 's/HTTPSTATUS\:.*//g')
  local http_status
  http_status=$(echo "$http_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
  # inspect the response code
  if [ "$http_status" -eq "200" ]; then
    # parse the response, append the indexes from the cluster to the global indexes variable
    echo "$http_body" | jq --raw-output --compact-output \
      --arg buckets "$BUCKETS" \
      --arg include_replicas "$INCLUDE_REPLICAS" \
      --arg cluster "$cluster" \
      '.indexes as $indexes |
      $buckets | gsub("\\*"; "") | split(",") as $buckets |
      $indexes |
        [ .[] | . as $current |
          select(
            (($buckets | length == 0) or (reduce $buckets[] as $item (false; if (. == false and $item == $current.bucket) then . = true else . end)))
            and
            ($include_replicas == "true" or ($include_replicas == "false" and ($current.index | contains("replica ") | not)))
          ) | {
            "cluster": $cluster,
            "index": $current.index,
            "bucket": $current.bucket,
            "scope": $current.scope,
            "collection": $current.collection,
            "hosts": $current.hosts,
            # strip off the WITH {...}
            "definition": ($current.definition | gsub(" WITH \\{.+$"; ""))
          }
        ] | unique | sort_by(.bucket, .scope, .collection, .index)
      '

      exit
  else
    debug "http_status: $http_status"
    debug "http_body: $http_body"
    error "Unable to reach the cluster: ${cluster} at ${url}"
    exit 1
  fi
}

# getClusterName
# -----------------------------------
# Retrieves the name of the cluster
# -----------------------------------
# shellcheck disable=SC2001
getClusterName() {
  local cluster="${1}"
  debug "cluster: $cluster"
  # call the index status api
  local url="$PROTOCOL://$cluster:$PORT/pools/default"
  debug "url: $url"
  local http_response
  http_response=$(curl -k \
    --user "$USERNAME:$PASSWORD" \
    --silent \
    --connect-timeout "$TIMEOUT" \
    --request GET \
    --write-out "HTTPSTATUS:%{http_code}" \
    "$url")
  local http_body
  http_body=$(echo "$http_response" | sed -e 's/HTTPSTATUS\:.*//g')
  local http_status
  http_status=$(echo "$http_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
  debug "http_status: $http_status"
  # inspect the response code
  if [ "$http_status" -eq "200" ]; then
     # parse the response, append the indexes from the cluster to the global indexes variable
     echo "$http_body" | jq --raw-output --compact-output \
      '.clusterName'
  else
    debug "http_status: $http_status"
    debug "http_body: $http_body"
    error "Unable to reach the cluster: ${cluster} at ${url}"
    exit 1
  fi
}

# ******************************************************************************************************
# *********************                DO NOT EDIT BELOW THIS LINE                **********************
# ******************************************************************************************************
# Template inspired by:
#  - https://github.com/oxyc/bash-boilerplate/blob/master/script.sh
#  - https://github.com/kvz/bash3boilerplate/blob/master/example.sh

set -o errexit # Exit on error. Append '||true' when you run the script if you expect an error.
set -o errtrace # Exit on error inside any functions or subshells.
set -o pipefail # Exit on piping, bash will remember & return the highest exitcode in a chain of pipes.
set -o nounset # Exit when undeclared variables are used

# magic variables for use within the script
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # the directory the script is being executed in
__script_path="${__dir}/$(basename "${BASH_SOURCE[0]}")" # the full path to the script
__script="$(basename "${__script_path}")" # the name of the script including the extension
__script_name="$(basename "${__script_path}" .sh)" # the name of the script without the extension
# shellcheck disable=SC2015
__invocation="$(printf %q "${__script_path}")$( (($#)) && printf ' %q' "$@" || true )" # the invocating command and options passed to the script at execution time

# Set Temp Directory
# -----------------------------------
# Create temp directory with three random numbers and the process ID
# in the name.  This directory is removed automatically at exit.
# -----------------------------------
tmp_dir="/tmp/${__script_name}.$RANDOM.$RANDOM.$RANDOM.$$"
(umask 077 && mkdir "${tmp_dir}") || {
  error "Could not create temporary directory! Exiting." && exit 1
}

# _cleanup
# -----------------------------------
# Remove any tmp files, if any
# -----------------------------------
_cleanup() {
  if [ -d "${tmp_dir}" ]; then
    rm -r "${tmp_dir}"
  fi
}

LOG_LEVEL=${LOG_LEVEL:=6} # 7 = debug -> 0 = emergency
NO_COLOR="${NO_COLOR:-}"
TRACE="0"

# _log
# -----------------------------------
# Handles all logging, all log messages are output to stderr so stdout can still be piped
#   Example: _log "info" "Some message"
# -----------------------------------
# shellcheck disable=SC2034
_log () {
  local log_level="${1}" # first option is the level, the rest is the message
  shift
  local color_success="\\x1b[32m"
  local color_debug="\\x1b[36m"
  local color_info="\\x1b[90m"
  local color_notice="\\x1b[34m"
  local color_warning="\\x1b[33m"
  local color_error="\\x1b[31m"
  local color_critical="\\x1b[1;31m"
  local color_alert="\\x1b[1;33;41m"
  local color_emergency="\\x1b[1;4;5;33;41m"
  local colorvar="color_${log_level}"
  local color="${!colorvar:-${color_error}}"
  local color_reset="\\x1b[0m"

  # If no color is set or a non-recognized terminal is used don't use colors
  if [[ "${NO_COLOR:-}" = "true" ]] || { [[ "${TERM:-}" != "xterm"* ]] && [[ "${TERM:-}" != "screen"* ]]; } || [[ ! -t 2 ]]; then
    if [[ "${NO_COLOR:-}" != "false" ]]; then
      color="";
      color_reset="";
    fi
  fi

  # all remaining arguments are to be printed
  local log_line=""

  while IFS=$'\n' read -r log_line; do
    echo -e "$(date +"%Y-%m-%d %H:%M:%S %Z") ${color}[${log_level}]${color_reset} ${log_line}" 1>&2
  done <<< "${@:-}"
}

# emergency
# -----------------------------------
# Handles emergency logging
# -----------------------------------
emergency() {
  _log emergency "${@}"; exit 1;
}

# success
# -----------------------------------
# Handles success logging
# -----------------------------------
success() {
  _log success "${@}"; true;
}

# alert
# -----------------------------------
# Handles alert logging
# -----------------------------------
alert() {
  [[ "${LOG_LEVEL:-0}" -ge 1 ]] && _log alert "${@}";
  true;
}

# critical
# -----------------------------------
# Handles critical logging
# -----------------------------------
critical() {
  [[ "${LOG_LEVEL:-0}" -ge 2 ]] && _log critical "${@}";
  true;
}

# error
# -----------------------------------
# Handles error logging
# -----------------------------------
error() {
  [[ "${LOG_LEVEL:-0}" -ge 3 ]] && _log error "${@}";
  true;
}

# warning
# -----------------------------------
# Handles warning logging
# -----------------------------------
warning() {
  [[ "${LOG_LEVEL:-0}" -ge 4 ]] && _log warning "${@}";
  true;
}

# notice
# -----------------------------------
# Handles notice logging
# -----------------------------------
notice() {
  [[ "${LOG_LEVEL:-0}" -ge 5 ]] && _log notice "${@}";
  true;
}

# info
# -----------------------------------
# Handles info logging
# -----------------------------------
info() {
  [[ "${LOG_LEVEL:-0}" -ge 6 ]] && _log info "${@}";
  true;
}

# debug
# -----------------------------------
# Handles debug logging and prepends the name of the that called debug in front of the message
# -----------------------------------
debug() {
  [[ "${LOG_LEVEL:-0}" -ge 7 ]] && _log debug "${FUNCNAME[1]}() ${*}";
  true;
}

# _exit
# -----------------------------------
# Non destructive exit for when script exits naturally.
# -----------------------------------
_exit() {
  _cleanup
  trap - INT TERM EXIT
  exit
}

# _error_report
# -----------------------------------
# Any actions that should be taken if the script is prematurely exited.
# -----------------------------------
_error_report() {
  _cleanup
  error "Error in ${__script} in ${1} on line ${2}"
  exit 1
}

# trap bad exits with custom _trap function
trap '_error_report "${FUNCNAME:-.}" ${LINENO}' ERR

# Set IFS to preferred implementation
IFS=$'\n\t'

# Iterate over options breaking --foo=bar into --foo bar, and handle common arguments like --debug, --log-level, --no-color
unset options
while (($#)); do
  case $1 in
    # If option is of type --foo=bar
    --?*=*) options+=("${1%%=*}" "${1#*=}") ;;
    --help) _usage >&2; _exit ;;
    --version) echo "${__script_name} ${version}"; _exit ;;
    --log-level) LOG_LEVEL=${2} && shift ;;
    --no-color) NO_COLOR=true ;;
    --debug) LOG_LEVEL="7" ;;
    --trace)
      TRACE="1"
      LOG_LEVEL="7"
    ;;
    # add --endopts for --
    --) options+=(--endopts) ;;
    # Otherwise, nothing special
    *) options+=("$1") ;;
  esac
  shift
done

if [ "${options:-}" != "" ]; then
  set -- "${options[@]}"
  unset options
fi

# parse the options
_options "$@"

# if trace has been set to 1 via the --trace argument enable tracing after the options have been parsed
if [[ "${TRACE}" == "1" ]]
then
  set -o xtrace
fi

# validate the options
_validate

# check dependencies
_dependencies

# call the main function
main

# cleanly exit
_exit
