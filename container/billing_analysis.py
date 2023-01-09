""" Cost & Usage Analysis script """

# See README.md for an explanation of how this script works.

import csv
import datetime
import json
import os
import sys
import tempfile
import time
import traceback
from enum import Enum
from gzip import GzipFile
from io import TextIOWrapper
from typing import Tuple, Type, Union

import boto3
import requests
from botocore.exceptions import ClientError
from dateutil import parser as dateutil_parser

# Switch to True to enable sanity checking of costs (e.g. if the script starts
# reporting that the numbers aren't matching).
DEBUG = False
# Turn these to True to force the associated cost to zero. By setting all but one
# to True (and one to False), this can help with tracking down missing costs or
# costs that are getting added multiple times.
DEBUG_FARGATE_COSTS = False
DEBUG_NATGW_COSTS = False
DEBUG_VOLUME_COSTS = False
DEBUG_INSTANCE_COSTS = False
DEBUG_EC2NW_COSTS = False

# Set to True if using the CodeLinaro APIs to save the costs.
SAVE_TO_CODELINARO = True

WARNINGS = True

CUR_BUCKET = None
RESULTS_BUCKET = None
CACHE_BUCKET = None
CW_VPC_FLOW_LOGS = None
CW_CLUSTER_LOGS = None
GITLAB_URL = None
GITLAB_TOKEN = ""
LOG_STREAM_NAME = ""
LOG_STREAM_TOKEN = None

# Constants for frequently used strings, to keep Sonar happy.
UNBLENDED_COST = "lineItem/UnblendedCost"
INSTANCE_ID = "resourceTags/user:InstanceID"
LINE_ITEM_ID = "identity/LineItemId"
NODEGROUP_NAME_TAG = "resourceTags/user:eks:nodegroup-name"
PRODUCT_CODE = "lineItem/ProductCode"
RESOURCE_ID = "lineItem/ResourceId"
USAGE_START_DATE = "lineItem/UsageStartDate"
USAGE_TYPE = "lineItem/UsageType"
USER_NAME_TAG = "resourceTags/user:Name"
PROVISIONER_NAME = "karpenter.sh/provisioner-name/"
ANALYSIS_LOG_GROUP = "ci-billing-analysis"

EXPECTED_BASED_COSTS = [
    "awskms",
    "AmazonCloudWatch",
    "AWSSecretsManager",
    "AmazonECR",  # Stores the container to run the script as a job
    "AWSLambda",  # Can be removed once Lambda is no longer used
    "AmazonApiGateway", # Used by CodeLinaro to run a k8s admission controller, deployed with Zappa
    "AWSSupportBusiness",
    # The following costs can be caused by Trusted Advisor. The amounts are small
    # but we need to allow for them otherwise they get classed as unallocated.
    "AWSQueueService",
    "AmazonSNS",
    "AmazonDynamoDB"
]


class LogLevel(Enum):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

############################
# CODELINARO SPECIFIC CODE #
############################

# Globals from env vars for CodeLinaro-specific code
AUTH0_CLIENT_ID = ""
AUTH0_CLIENT_SECRET_KEY = ""
AUTH0_CLIENT_AUDIENCE = ""
AUTH0_CLIENT_URL = ""
CLO_API_URL = ""

def get_secret(secret_name: str):
    """Retrieve secrets from AWS Secrets Manager

    Raises:
        e: any unhandled exception - not sure why as it doesn't catch any
    """
    global AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET_KEY, GITLAB_TOKEN
    client = boto3.client('secretsmanager')

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = json.loads(get_secret_value_response['SecretString'])
    AUTH0_CLIENT_ID = secret["AUTH0_CLIENT_ID"]
    AUTH0_CLIENT_SECRET_KEY = secret["AUTH0_CLIENT_SECRET_KEY"]
    GITLAB_TOKEN = secret["GITLAB_TOKEN"]


def sync_codelinaro_project_costs(cur_file: str):
    """Send any new/updated project costs to CodeLinaro's API

    Args:
        cur_file (str): S3 CUR file key
    """
    previous_data = []

    # If a file already exists on S3, read it into previous_data
    path = date_range_from_cur_path(cur_file)
    year_month = path[:6]
    client = boto3.client("s3")
    try:
        response = client.get_object(
            Bucket=RESULTS_BUCKET,
            Key=f"{path}/project_costs.json"
        )
        json_file_reader = response['Body'].read()
        previous_data = json.loads(json_file_reader)
    except client.exceptions.NoSuchKey:
        pass

    auth_token = get_token_from_auth0()

    # Iterate through the projects, pipelines and jobs. If
    # we have any costs that don't exist in previous_data or
    # are a different value, tell CodeLinaro.
    for project in PROJECT_COSTS:
        compare_project_costs(previous_data, auth_token, project)
        compare_cache_costs(previous_data, year_month, auth_token, project)


def compare_cache_costs(previous_data: list, year_month: str, auth_token: str, project: dict):
    """Save cache costs to CodeLinaro if there are costs

    Args:
        previous_data (list): cost data saved from previous run
        year_month (str): the year and month for this cost
        auth_token (str): CodeLinaro API auth
        project (dict): dict of calculated project costs
    """
    if "cache_cost" in project:
        project_id = project["project_id"]
        cache_cost = project["cache_cost"]
        previous_cost = get_previous_cache_cost(previous_data, project_id)
        save_codelinaro_project_cache_cost(
            project_id, year_month, cache_cost, previous_cost, auth_token)


def compare_project_costs(previous_data: list, auth_token: str, project: dict):
    """Save project costs to CodeLinaro if we have any

    Args:
        previous_data (list): cost data saved from previous run
        auth_token (str): CodeLinaro API auth
        project (dict): dict of calculated project costs
    """
    if "pipelines" in project:
        counter = 1
        last_output = ""
        pipeline_len = len(project["pipelines"])
        for pipeline in project["pipelines"]:
            new_output = f"Saving job costs: {int(counter*100/pipeline_len)}%"
            if new_output != last_output:
                output(new_output, LogLevel.INFO)
                last_output = new_output
            counter += 1
            for job in pipeline["jobs"]:
                project_id = project["project_id"]
                pipeline_id = pipeline["pipeline_id"]
                job_id = job["job_id"]
                job_cost = job["cost"]
                previous_cost = get_previous_cost(
                    previous_data, project_id, pipeline_id, job_id)
                save_codelinaro_job_cost(
                    project_id, pipeline_id, job_id, job_cost, previous_cost, auth_token)


def get_previous_cost(data: list, project_id: str, pipeline_id: str, job_id: str) -> Union[float, None]:
    """Find the previous cost, if there is one, for this job

    Args:
        data (list): the costs saved from the previous run
        project_id (str): ID for the project to retrieve the costs for
        pipeline_id (str): ID for the pipeline to retrieve the costs for
        job_id (str): ID for the CI job to retrieve the costs for

    Returns:
        Union[float, None]: previous cost or None if there wasn't one
    """
    project = iterate_to_find(data, "project_id", project_id)
    pipelines = project.get("pipelines", [])
    pipeline = iterate_to_find(pipelines, "pipeline_id", pipeline_id)
    jobs = pipeline.get("jobs", [])
    job = iterate_to_find(jobs, "job_id", job_id)
    return job.get("cost", None)


def iterate_to_find(data: list, identifier: str, value: str) -> dict:
    """Loop through the specified list looking for a match

    Args:
        data (list): the data to search through - a list of dicts
        identifier (str): the key to look for
        value (str): the value to check for

    Returns:
        dict: the dict that matches the identifier and value
    """
    for item in data:
        if item[identifier] == value:
            return item
    return {}


def get_previous_cache_cost(data: list, project_id: str) -> Union[float, None]:
    """Find the previous cache cost, if there is one, for this project

    Args:
        data (list): data saved from the previous run
        project_id (str): the project ID to match against

    Returns:
        Union[float, None]: previous cost or None if there wasn't one
    """
    for project in data:
        if project["project_id"] == project_id:
            return project.get("cache_cost", None)
    return None


def get_token_from_auth0() -> str:
    """Get an authorisation token

    Returns:
        str: access token for CodeLinaro
    """
    body = {
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET_KEY,
        "audience": AUTH0_CLIENT_AUDIENCE,
        "grant_type": "client_credentials"
    }
    response = requests.post(
        AUTH0_CLIENT_URL,
        json=body
    )
    response.raise_for_status()
    return response.json()["access_token"]


def save_codelinaro_job_cost(project_id: str, pipeline_id: str, job_id: str, job_cost: float, previous_cost: Union[float, None], auth: str):
    """Call the CodeLinaro API to save the job cost

    Args:
        project_id (str): ID of the project for this cost
        pipeline_id (str): ID of the pipeline for this cost
        job_id (str): ID of the CI job for this cost
        job_cost (float): the calculated cost for this job
        previous_cost (Union[float, None]): the previous cost or None if there isn't one
        auth (str): API access token
    """
    if project_id is None or pipeline_id is None or job_id is None:
        if DEBUG:
            output(
                f"Skipping cost ({job_cost:.10f}) because one or more of {project_id}/{pipeline_id}/{job_id} is None", LogLevel.WARNING)
        return

    if previous_cost is not None and equal_to_x_dp(job_cost, previous_cost):
        if DEBUG:
            output(
                f"Skipping cost for {project_id}/{pipeline_id}/{job_id} because it hasn't changed from last time", LogLevel.INFO)
        return

    if previous_cost is None:
        previously = ""
    else:
        previously = f", previously {previous_cost:.10f}"

    if DEBUG:
        output(
            f"Saving cost ({job_cost:.10f}{previously}) of {project_id}/{pipeline_id}/{job_id} to CodeLinaro API", LogLevel.INFO)
    body = {
        "repoID": project_id,
        "pipelineID": pipeline_id,
        "jobID": job_id,
        "cost": job_cost
    }
    header = {
        "Authorization": f"Bearer {auth}"
    }
    url = f"{CLO_API_URL}/ci/job"
    response = requests.post(
        url,
        headers=header,
        json=body
    )
    response.raise_for_status()


def save_codelinaro_project_cache_cost(project_id: str, year_month: str, cache_cost: float, previous_cost: Union[float, None], auth: str):
    """Call the CodeLinaro API to save the cache cost

    Args:
        project_id (str): project ID for this cost
        year_month (str): year and month for this cost
        cache_cost (float): calculated cache cost for this project
        previous_cost (Union[float, None]): previous cost or None if there wasn't one
        auth (str): API access token
    """
    if previous_cost is not None and equal_to_x_dp(cache_cost, previous_cost):
        output(
            f"Skipping cache cost for {project_id} because it hasn't changed from last time", LogLevel.INFO
        )
        return

    if previous_cost is None:
        previously = ""
    else:
        previously = f", previously {previous_cost:.10f}"

    output(
        f"Saving cost ({cache_cost:.10f}{previously}) of {project_id}/cache to CodeLinaro API", LogLevel.INFO)
    body = {
        "repoID": project_id,
        "date": year_month,
        "cost": cache_cost
    }
    url = f"{CLO_API_URL}/ci/cache"
    header = {
        "Authorization": f"Bearer {auth}"
    }
    response = requests.post(
        url,
        headers=header,
        json=body
    )
    response.raise_for_status()


def initialise_codelinaro_globals():
    """Set the CodeLinaro globals from env vars
    """
    global AUTH0_CLIENT_AUDIENCE, AUTH0_CLIENT_URL, CLO_API_URL
    secret_name = check_and_return("SECRET_NAME")
    get_secret(secret_name)
    AUTH0_CLIENT_AUDIENCE = check_and_return("AUTH0_CLIENT_AUDIENCE")
    AUTH0_CLIENT_URL = check_and_return("AUTH0_CLIENT_URL")
    CLO_API_URL = check_and_return("CLO_API_URL")

###################################
# END OF CODELINARO SPECIFIC CODE #
###################################

def output(string: str, level: LogLevel):
    """Handle the output request

    Args:
        string (str): the string to output
        level (LogLevel): the log level for this message
    """
    # DEBUG is only output if DEBUG is True
    # INFO always goes to the CloudWatch logs
    # WARNING only goes if we aren't suppressing warnings
    # ERROR sets the processing error flag
    global SUPPRESSED_WARNING_COUNT, PROCESSING_ERROR, LOG_STREAM_TOKEN
    if level == LogLevel.DEBUG and not DEBUG:
        return
    if WARNINGS and level == LogLevel.WARNING:
        SUPPRESSED_WARNING_COUNT += 1
        return
    # Add an appropriate prefix to the string
    if level == LogLevel.ERROR:
        string = f"ERROR! {string}"
        PROCESSING_ERROR = True
    elif level == LogLevel.WARNING:
        string = f"Warning! {string}"
    if LOG_STREAM_NAME == "":
        print(string)
        return

    client = boto3.client('logs')
    while True:
        try:
            if LOG_STREAM_TOKEN is None:
                response = client.put_log_events(
                    logGroupName=ANALYSIS_LOG_GROUP,
                    logStreamName=LOG_STREAM_NAME,
                    logEvents=[
                        {
                            'timestamp': int(round(time.time() * 1000)),
                            'message': string
                        }
                    ]
                )
            else:
                response = client.put_log_events(
                    logGroupName=ANALYSIS_LOG_GROUP,
                    logStreamName=LOG_STREAM_NAME,
                    logEvents=[
                        {
                            'timestamp': int(round(time.time() * 1000)),
                            'message': string
                        }
                    ],
                    sequenceToken=LOG_STREAM_TOKEN
                )
            LOG_STREAM_TOKEN = response["nextSequenceToken"]
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ThrottlingException':
                time.sleep(3)
            else:
                raise


def perform_billing_analysis():
    """ The main function for the script """
    try:
        check_environment_variables()
        set_up_cloudwatch()
        # Process this month
        today = datetime.date.today()
        process_billing_report(today.month, today.year)
        # Process last month if there was anything
        last_month = today.month - 1
        if last_month < 1:
            last_month = last_month + 12
            last_month_year = today.year - 1
        else:
            last_month_year = today.year
        process_billing_report(last_month, last_month_year)
        if not PROCESSING_ERROR:
            output("Processing has completed", LogLevel.INFO)
    except Exception as exc:
        output(
            "An exception has occurred in the CI Billing Analysis Script", LogLevel.ERROR)
        output(str(exc), LogLevel.ERROR)
        output(''.join(traceback.format_tb(exc.__traceback__)), LogLevel.ERROR)


def set_up_cloudwatch():
    """ Sets up the logging infrastructure """
    create_cloudwatch_log_group()
    create_cloudwatch_log_stream()


def create_cloudwatch_log_group():
    """ If it doesn't already exist, create the log group """
    client = boto3.client('logs')
    response = client.describe_log_groups(
        logGroupNamePrefix=ANALYSIS_LOG_GROUP
    )
    log_groups = response["logGroups"]
    for lg in log_groups:
        if lg["logGroupName"] == ANALYSIS_LOG_GROUP:
            return
    response = client.create_log_group(
        logGroupName=ANALYSIS_LOG_GROUP
    )


def create_cloudwatch_log_stream():
    """ Create a new log stream for this run of the script """
    global LOG_STREAM_NAME
    if LOG_STREAM_NAME != "":
        return

    LOG_STREAM_NAME = str(datetime.datetime.now())
    # Replace colons with dashes
    LOG_STREAM_NAME = LOG_STREAM_NAME.replace(":", "-")
    client = boto3.client('logs')
    client.create_log_stream(
        logGroupName=ANALYSIS_LOG_GROUP,
        logStreamName=LOG_STREAM_NAME
    )


def process_billing_report(month: int, year: int):
    """Process the billing report for the specified month

    Args:
        month (int): month to process
        year (int): year to process
    """
    global ANALYSIS_CACHE
    next_month = month + 1
    if next_month <= 12:
        next_year = year
    else:
        next_year = year+1
        next_month = next_month-12
    date_range = f"{year}{month:02}01-{next_year}{next_month:02}01"
    last_cur_file = None
    # Start by trying to retrieve a file that tells us the last CUR report used
    last_cur_file = load_from_s3(date_range, "cur_used.txt", None)
    # and any existing analysis cache
    ANALYSIS_CACHE = load_from_s3(date_range, "analysis_cache.json", {})
    # If we don't have a last CUR file, figure out the date range we
    # want to be checking for.
    if last_cur_file is None:
        output(f"No previous CUR file used for {month}/{year}", LogLevel.INFO)
    # Now scan all of the files in the CUR bucket, looking for files in that date range
    # and find the latest one.
    s3_resource = boto3.resource('s3')
    cur_bucket = s3_resource.Bucket(CUR_BUCKET)  # type: ignore
    found_latest = None
    for obj in cur_bucket.objects.all():
        obj_key = obj.key
        parts = obj_key.split("/")
        if obj_key.endswith(".csv.gz") and \
                parts[2] == date_range and \
                (found_latest is None or found_latest < obj_key):
            found_latest = obj_key
    # When we get to here, found_latest should be the latest CUR file for the required
    # date range, or None if there aren't any.
    if found_latest is None:
        output(f"No CUR files for date range {date_range}", LogLevel.INFO)
        return
    if found_latest == last_cur_file:
        output(f"No newer CUR file since {last_cur_file}", LogLevel.INFO)
        return
    process_s3_object(found_latest)


def check_environment_variables():
    """ Get the variables for the CloudWatch log groups """
    global CUR_BUCKET, RESULTS_BUCKET, CACHE_BUCKET, CW_VPC_FLOW_LOGS, CW_CLUSTER_LOGS, GITLAB_URL
    CUR_BUCKET = check_and_return("CUR_BUCKET_NAME")
    RESULTS_BUCKET = check_and_return("RESULTS_BUCKET_NAME")
    CACHE_BUCKET = check_and_return("CACHE_BUCKET_NAME")
    CW_VPC_FLOW_LOGS = check_and_return("CW_VPC_FLOW_LOGS")
    CW_CLUSTER_LOGS = check_and_return("CW_CLUSTER_LOGS")
    GITLAB_URL = check_and_return("GITLAB_URL")
    if GITLAB_URL[-1] != "/":
        GITLAB_URL += "/"
    if SAVE_TO_CODELINARO:
        initialise_codelinaro_globals()
    else:
        global GITLAB_TOKEN
        GITLAB_TOKEN = check_and_return("GITLAB_TOKEN")


def check_and_return(os_var: str) -> str:
    """Return the value of the specified os env var

    Args:
        os_var (str): environment variable to retrieve

    Returns:
        str: value of the variable
    """
    if os_var not in os.environ:
        sys.exit(f"{os_var} is not defined as an environment variable")
    return os.environ[os_var]


def process_s3_object(s3_key: str):
    """Do some checks and then analyse if appropriate

    Args:
        s3_key (str): S3 file key
    """
    output(f"Processing CUR file {s3_key}", LogLevel.INFO)
    initialise_billing_globals()

    # Read in the CUR file and either add each cost to BASE, UNALLOCATED or
    # mark it as pending.
    if CUR_BUCKET is not None:
        process_cur_report(CUR_BUCKET, s3_key)

    if DEBUG:
        # Sanity check the totals so far ...
        total_test = sanity_check_totals(PENDING_FARGATE_COSTS,
                                         "PENDING_FARGATE_COSTS")
        total_test += sanity_check_totals(PENDING_NATGW_COSTS,
                                          "PENDING_NATGW_COSTS")
        total_test += sanity_check_totals(PENDING_VOLUME_COSTS,
                                          "PENDING_VOLUME_COSTS")
        total_test += sanity_check_totals(PENDING_INSTANCE_COSTS,
                                          "PENDING_INSTANCE_COSTS")
        total_test += sanity_check_totals(PENDING_EC2NW_COSTS,
                                          "PENDING_EC2NW_COSTS")
        total_test += totalise_base_costs(False)
        total_test += totalise_unallocated_costs()
        output(
            f"Sanity check: Total cost allocated or pending is {total_test:.10f}", LogLevel.DEBUG)

    # Now process the pending costs ...
    # Start by sorting the usage start date keys so that we can do this in
    # chronological order.
    USAGE_START_KEYS.sort()
    counter = 1

    # Now go through each hour by hour, analyzing the pending costs.
    last_output = ""
    usk_len = len(USAGE_START_KEYS)
    for start in USAGE_START_KEYS:
        new_output = f"Reading CUR: {int(counter*100/usk_len)}%: {start}" if DEBUG else f"Reading CUR: {int(counter*100/len(USAGE_START_KEYS))}%"
        if new_output != last_output:
            output(new_output, LogLevel.INFO)
            last_output = new_output
        counter += 1

        nat_traffic_cost = 0.0
        nat_gateway = None
        if start in PENDING_NATGW_COSTS:
            nat_traffic_cost, nat_gateway = process_pending_natgw_costs(start)

        if start in PENDING_FARGATE_COSTS:
            # If there were builds running in Fargate, the NAT traffic cost will
            # be split according to the percentage allocation from the VPC flow
            # logs ... in which case, nat_traffic_cost gets set to 0.0. HOWEVER, if
            # something goes awry with the logs (e.g. cannot get the IP address for
            # the pods and so cannot divine the VPC flow logs), the original cost
            # is left to be added back to the base costs.
            nat_traffic_cost = process_pending_fargate_costs(
                start, nat_traffic_cost, nat_gateway)

        if start in PENDING_INSTANCE_COSTS:
            process_pending_instance_costs(start)

        if start in PENDING_EC2NW_COSTS:
            process_pending_ec2nw_costs(start)

        # Add any unallocated NAT cost to the base cost
        if nat_traffic_cost != 0.0:
            add_cost_to_dict(BASE_COSTS, start,
                             "NAT traffic", nat_traffic_cost)

    # It is possible for EC2 network costs to appear in the CUR without the
    # corresponding EC2 instances. This would normally result in those network
    # cost entries going unprocessed, resulting in an error. To avoid that
    # scenario, we explicitly check for network costs without a corresponding
    # EC2 instance and, if found, mark them as unallocated instead as a temporary
    # measure.
    check_for_unprocessed_ec2nw_costs()

    totalise_costs(s3_key)


def check_for_unprocessed_ec2nw_costs():
    """If there are unprocessed ec2nw costs due to instances not present in CUR, put them
       (temporarily) as unallocated.
    """
    for date in PENDING_EC2NW_COSTS:
        for line in PENDING_EC2NW_COSTS[date]:
            if line[LINE_ITEM_ID] != "" and missing_ec2_instance(line[RESOURCE_ID]):
                output(
                    f"Moving unprocessed EC2NW cost to unallocated because resource ID {line[RESOURCE_ID]} cannot be found in CUR file. This should be a temporary situation until the next file is processed.",
                    LogLevel.WARNING
                )
                add_to(UNALLOCATED_COSTS, line)


def missing_ec2_instance(resource_id: str) -> bool:
    """Looks for the resource ID in the list of EC2 instances processed and indicates whether
       or not it is known.

    Args:
        resource_id (str): EC2 resource ID to look for

    Returns:
        bool: True if missing otherwise False
    """
    return resource_id not in EC2_INSTANCE_IDS


def sanity_check_totals(pending: dict, pending_name: str) -> float:
    """Add up all of the costs from this pending dict

    Args:
        pending (dict): the dict to add up
        pending_name (str): the name of the dict

    Returns:
        float: the total
    """
    total = 0.0
    for date in pending:
        for row in pending[date]:
            total += float(row[UNBLENDED_COST])
    output(f"Total for {pending_name} is {total:.10f}", LogLevel.INFO)
    return total


# Billing analysis portion of the script

PROJECT_COSTS = []
BASE_COSTS = {}
UNALLOCATED_COSTS = {}

PENDING_FARGATE_COSTS = {}
PENDING_NATGW_COSTS = {}
PENDING_VOLUME_COSTS = {}
PENDING_INSTANCE_COSTS = {}
PENDING_EC2NW_COSTS = {}

DEFAULT_NODE_INSTANCES = []
DEFAULT_NODE_GROUPS = []
USAGE_START_KEYS = []
EC2_INSTANCE_IDS = []
ANALYSIS_CACHE = {}

TOTAL_COST_FROM_CUR = 0.0
TOTAL_ALLOCATED = 0.0

CUR_FILE_ROW_COUNT = 0
CUR_FILE_PROCESSED_COUNT = 0
CUR_FILE = []

SUPPRESSED_WARNING_COUNT = 0
PROCESSING_ERROR = False


def initialise_billing_globals():
    """ (Re)initialise the globals used by the billing code """
    global PROJECT_COSTS, BASE_COSTS, UNALLOCATED_COSTS
    global PENDING_FARGATE_COSTS, PENDING_NATGW_COSTS, PENDING_VOLUME_COSTS, PENDING_INSTANCE_COSTS, PENDING_EC2NW_COSTS
    global DEFAULT_NODE_INSTANCES, DEFAULT_NODE_GROUPS, USAGE_START_KEYS, EC2_INSTANCE_IDS
    global TOTAL_COST_FROM_CUR, TOTAL_ALLOCATED
    global CUR_FILE_ROW_COUNT, CUR_FILE_PROCESSED_COUNT, CUR_FILE
    global SUPPRESSED_WARNING_COUNT, PROCESSING_ERROR

    PROJECT_COSTS = []
    BASE_COSTS = {}
    UNALLOCATED_COSTS = {}

    PENDING_FARGATE_COSTS = {}
    PENDING_NATGW_COSTS = {}
    PENDING_VOLUME_COSTS = {}
    PENDING_INSTANCE_COSTS = {}
    PENDING_EC2NW_COSTS = {}

    DEFAULT_NODE_INSTANCES = []
    DEFAULT_NODE_GROUPS = []
    USAGE_START_KEYS = []
    EC2_INSTANCE_IDS = []

    TOTAL_COST_FROM_CUR = 0.0
    TOTAL_ALLOCATED = 0.0

    CUR_FILE_ROW_COUNT = 0
    CUR_FILE_PROCESSED_COUNT = 0
    if DEBUG:
        CUR_FILE = []

    SUPPRESSED_WARNING_COUNT = 0
    PROCESSING_ERROR = False


def date_range_from_cur_path(cur_file: str) -> str:
    """Extract the date range from the CUR filename 

    Args:
        cur_file (str): the CUR filename

    Returns:
        str: the date range extracted from the filename
    """
    parts = cur_file.split("/")
    return parts[2]


def save_to_s3(cur_file: str, data: Type, filename: str):
    """Save the data as a JSON-encoded file in the results bucket

    Args:
        cur_file (str): the origiinal CUR filename
        data (Type): the data to save to S3 in JSON format
        filename (str): the filename to save it under
    """
    path = date_range_from_cur_path(cur_file)
    # Save the data to a temporary file
    temp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    temp_filename = temp.name
    json.dump(data, temp)
    temp.close()
    # Upload that file to S3
    client = boto3.client("s3")
    client.upload_file(temp_filename, RESULTS_BUCKET, f"{path}/{filename}")
    # Delete the temporary file
    os.remove(temp_filename)


def load_from_s3(date_range: str, filename: str, if_not_found: Union[None, dict]) -> Type:
    """Load the specified file from the specified CUR folder

    Args:
        date_range (str): which month (date range) to retrieve the data from
        filename (str): the leafname of the file to read
        if_not_found (Union[None, dict]): what to return if that file doesn't exist

    Returns:
        Type: either the data read from the file or the value of if_not_found
    """
    content = if_not_found
    s3 = boto3.client('s3')
    try:
        json_object = s3.get_object(
            Bucket=RESULTS_BUCKET, Key=f"{date_range}/{filename}")
        json_file_reader = json_object['Body'].read()
        content = json.loads(json_file_reader)
    except s3.exceptions.from_code("NoSuchKey"):
        pass
    return content


# Commented out the lines to emit the individual costs as they mostly get duplicated
# when syncing the costs to CodeLinaro API. Commented out rather than deleted to allow
# for easy restoration if required.
def totalise_project_costs() -> float:
    """Add up the project costs

    Returns:
        float: the month's total project costs so far
    """
    month_project_total = 0.0
    for project in PROJECT_COSTS:
        pipelines = project.get("pipelines", [])
        for pipeline in pipelines:
            for job in pipeline["jobs"]:
                job_cost = job["cost"]
                # project_id = project["project_id"]
                # pipeline_id = pipeline["pipeline_id"]
                # job_id = job["job_id"]
                # output(
                #     f"{project_id} > {pipeline_id} > {job_id}: {job_cost:.10f}", LogLevel.INFO)
                month_project_total += job_cost
        if "cache_cost" in project:
            cost = project["cache_cost"]
            # project_id = project["project_id"]
            # output(f"{project_id} > cache cost: {cost:.10f}", LogLevel.INFO)
            month_project_total += cost
    output(f"Projects total cost: {month_project_total:.10f}", LogLevel.INFO)
    return month_project_total


def totalise_base_costs(output_each_cost: bool) -> float:
    """Add up the base costs

    Returns:
        float: the month's base costs so far
    """
    month_base_total = 0.0
    for date in BASE_COSTS:
        base_total = 0.0
        for key in BASE_COSTS[date]:
            if output_each_cost:
                output(
                    f"Base cost: {key} - {BASE_COSTS[date][key]:.10f}", LogLevel.INFO)
            base_total += BASE_COSTS[date][key]
        month_base_total += base_total
    output(f"Base cost for month: {month_base_total:.10f}", LogLevel.INFO)
    return month_base_total


def totalise_unallocated_costs() -> float:
    """Add up the unallocated costs

    Returns:
        float: the month's unallocated costs so far
    """
    month_unallocated_total = 0.0
    for date in UNALLOCATED_COSTS:
        unallocated_total = 0.0
        for key in UNALLOCATED_COSTS[date]:
            output(
                f"Unallocated cost: {key} - {UNALLOCATED_COSTS[date][key]}", LogLevel.INFO)
            unallocated_total += UNALLOCATED_COSTS[date][key]
        output(
            f"Unallocated cost total for {date}: {unallocated_total:.10f}", LogLevel.INFO)
        month_unallocated_total += unallocated_total
    if month_unallocated_total != 0.0:
        output(
            f"Unallocated cost for month: {month_unallocated_total:.10f}", LogLevel.INFO)
    return month_unallocated_total


def equal_to_x_dp(value1: float, value2: float, dp: int=10) -> bool:
    """Compare two floats to the specified number of decimal places

    Args:
        value1 (float): value 1
        value2 (float): value 2
        dp (int): number of decimal places, default 10

    Returns:
        bool: true if they are equal to the number of decimal places, otherwise false
    """
    str_value1 = "{value1:.{dp}f}".format(value1=value1, dp=dp)
    str_value2 = "{value2:.{dp}f}".format(value2=value2, dp=dp)
    return str_value1 == str_value2


def totalise_costs(cur_file: str):
    """Add all the costs up and export them

    Args:
        cur_file (str): the CUR filename, used to determine where to save the results
    """
    costs_found = totalise_project_costs()
    if not equal_to_x_dp(costs_found, TOTAL_ALLOCATED):
        output(
            f"Total allocated to projects ({TOTAL_ALLOCATED:.10f}) differs from total cost",
            LogLevel.ERROR)
    costs_found += totalise_base_costs(True)
    costs_found += totalise_unallocated_costs()

    if not equal_to_x_dp(costs_found, TOTAL_COST_FROM_CUR, dp=2):
        output(
            f"Problem with cost allocation. Costs found={costs_found:.10f}, costs from CUR={TOTAL_COST_FROM_CUR:.10f}, difference = {TOTAL_COST_FROM_CUR - costs_found:.10f}",
            LogLevel.ERROR)

    if CUR_FILE_ROW_COUNT != CUR_FILE_PROCESSED_COUNT:
        output(
            f"Rows found: {CUR_FILE_ROW_COUNT}, rows processed: {CUR_FILE_PROCESSED_COUNT}",
            LogLevel.ERROR)
    if DEBUG:
        for row in CUR_FILE:
            if row[LINE_ITEM_ID] != "":
                output(
                    f"{row[LINE_ITEM_ID]} - {row[PRODUCT_CODE]} - {row[RESOURCE_ID]} - {row[USAGE_START_DATE]} - {row[USAGE_TYPE]} - {row[UNBLENDED_COST]}",
                    LogLevel.DEBUG
                )

    sanity_check_pending(PENDING_FARGATE_COSTS, "PENDING_FARGATE_COSTS")
    sanity_check_pending(PENDING_NATGW_COSTS, "PENDING_NATGW_COSTS")
    sanity_check_pending(PENDING_VOLUME_COSTS, "PENDING_VOLUME_COSTS")
    sanity_check_pending(PENDING_INSTANCE_COSTS, "PENDING_INSTANCE_COSTS")
    sanity_check_pending(PENDING_EC2NW_COSTS, "PENDING_EC2NW_COSTS")

    if SUPPRESSED_WARNING_COUNT != 0:
        output(
            f"{SUPPRESSED_WARNING_COUNT} warnings have been suppressed", LogLevel.INFO)

    if not PROCESSING_ERROR:
        if SAVE_TO_CODELINARO:
            sync_codelinaro_project_costs(cur_file)
        save_to_s3(cur_file, PROJECT_COSTS, "project_costs.json")
        save_to_s3(cur_file, BASE_COSTS, "base_costs.json")
        save_to_s3(cur_file, UNALLOCATED_COSTS, "unallocated_costs.json")
        save_to_s3(cur_file, cur_file, "cur_used.txt")
        save_to_s3(cur_file, ANALYSIS_CACHE, "analysis_cache.json")
    else:
        output("Cost files have not been saved due to a processing error", LogLevel.INFO)


def sanity_check_pending(pending: dict, pending_name: str):
    """Check that all of the pending costs have been used somewhere

    Args:
        pending (dict): one of the PENDING dictionaries
        pending_name (str): the name of the passed pending dictionary
    """
    count = 0
    total = 0
    for date in pending:
        for test in pending[date]:
            if test[LINE_ITEM_ID] != "":
                count += 1
            total += 1
    if count != 0:
        output(
            f"{pending_name}: {count} out of {total} not processed", LogLevel.ERROR)


def processed_this_row(row: dict):
    """Mark this row to show we've processed it and increment the counter

    Args:
        row (dict): the row that has been processed
    """
    global CUR_FILE_PROCESSED_COUNT
    row[LINE_ITEM_ID] = ""  # Show we've allowed for this cost
    CUR_FILE_PROCESSED_COUNT += 1


def process_pending_natgw_costs(start_time: str) -> Tuple[float, Union[None, str]]:
    """Calculate the total cost of all NAT traffic

    Args:
        start_time (str): the start time to look for

    Returns:
        Tuple[float, Union[None, str]]: returns the cost plus the NAT gateway ID or None if not found
    """
    nat_gateway = None

    # What is the total NAT gateway cost?
    network_total_cost = 0.0
    for net in PENDING_NATGW_COSTS[start_time]:
        resource_id = net[RESOURCE_ID]
        network_total_cost += float(net[UNBLENDED_COST])
        processed_this_row(net)
        this_nat = extract_nat_gateway(resource_id)
        if this_nat is None:
            output(
                f"Got network cost that isn't for a NAT gateway: {resource_id}",
                LogLevel.WARNING)
        elif nat_gateway is None:
            nat_gateway = this_nat
        elif nat_gateway != this_nat:
            output(
                f"More than one NAT gateway: {nat_gateway} vs {this_nat}",
                LogLevel.WARNING)
    return network_total_cost, nat_gateway


def extract_job_data(costs: dict, start_time: str) -> dict:
    """Build a dict of job & pod IDs, keyed by resource ID, for further processing

    Args:
        costs (dict): a dictionary of costs from which to extract the desired data
        start_time (str): the start time to look for

    Returns:
        dict: dict of job & pod IDs, keyed by resource ID
    """
    job_data = {}
    for proj in costs[start_time]:
        pod_start = dateutil_parser.isoparse(proj[USAGE_START_DATE])
        pod_end = dateutil_parser.isoparse(proj["lineItem/UsageEndDate"])
        # In testing, the CUR file could report a usage start and end date that
        # was an hour out, so we go for an hour earlier start and an hour later
        # end to make sure log searches work.
        pod_start = pod_start + datetime.timedelta(hours=-1)
        pod_end = pod_end + datetime.timedelta(hours=1)

        resource_id = proj[RESOURCE_ID]
        job_data.setdefault(resource_id, [])
        details = get_resource_details(resource_id, pod_start, pod_end)

        # We will always have at least one entry to process, even if there were
        # no runners.
        process_job_details(details, resource_id, proj,
                            job_data, pod_start, pod_end)
    return job_data


def process_job_details(details: list, resource_id: str, proj: dict, job_data: dict, pod_start: datetime.datetime, pod_end: datetime.datetime):
    """Given a list of jobs that ran on a node, add the details of the runners on that node to the job_data dict

    Args:
        details (list): list of jobs to process
        resource_id (str): the node's resource ID
        proj (dict): the line from the CUR file to be processed
        job_data (dict): job data accrued so far
        pod_start (datetime.datetime): start point for checking results
        pod_end (datetime.datetime): end point for checking results
    """
    for detail in details:
        if detail["job_id"] is None:
            output(
                f"Node {resource_id} cost {proj[UNBLENDED_COST]} but no runners", LogLevel.DEBUG)
            return

        # See if this has already been added to the job data
        known_jobs = job_data[resource_id]
        matched_job = None
        for job in known_jobs:
            if job["project_id"] == detail["project_id"] and \
                job["pipeline_id"] == detail["pipeline_id"] and \
                    job["job_id"] == detail["job_id"]:
                matched_job = job
                break

        # If not, add it.
        # If it has, extend the start/end times if required.
        if matched_job is None:
            known_jobs.append(detail)
        else:
            if pod_start < detail["pod_start"]:
                detail["pod_start"] = pod_start
            if detail["pod_end"] < pod_end:
                detail["pod_end"] = pod_end


def get_resource_details(resource_id: str, pod_start: datetime.datetime, pod_end: datetime.datetime) -> list:
    """Return project ID, job ID and pod name for the resource

    Args:
        resource_id (str): resource ID from CUR file for this cost
        pod_start (datetime.datetime): when do we want to start looking for the pod?
        pod_end (datetime.datetime): when do we want to stop looking for the pod?

    Returns:
        list: list of one or more CI jobs that ran on that resource
    """
    if resource_id.startswith("arn:aws:eks:"):
        return fargate_pod_details(resource_id, pod_start, pod_end)
    return ec2_node_details(resource_id, pod_start, pod_end)


def ensure_dict_cost_keys_exist(project_id: str, key: str, cost_dict: dict):
    """Make sure that the keys exist in the specified dict

    Args:
        project_id (str): project ID
        key (str): what do we want to save the cost under?
        cost_dict (dict): the dict to add the initial cost keys to
    """
    cost_dict.setdefault(project_id, {})
    cost_dict[project_id].setdefault(key, 0.0)


def find_dict_in_list(list_to_check: list, dict_key: str, dict_value: str) -> dict:
    """Find, adding if required, the specified dictionary in the list

    Args:
        list_to_check (list): the list to look in for the dict
        dict_key (str): the key to check, e.g. "project_id"
        dict_value (str): the value to check, e.g. the project's ID

    Returns:
        dict: the found dict otherwise a new empty dictionary
    """
    for entry in list_to_check:
        if dict_key in entry and entry[dict_key] == dict_value:
            return entry
    new_dict = {}
    list_to_check.append(new_dict)
    # Just return an empty dict so that the caller can initialise it as required
    return new_dict


def add_cost_to_project(project_id: str, pipeline_id: str, job_id: str, cost: float):
    """Add the cost to the specified project/build

    Args:
        project_id (str): project ID
        pipeline_id (str): pipeline ID
        job_id (str): job ID
        cost (float): cost to add
    """
    global TOTAL_ALLOCATED

    # Find the project object
    project_in_list = find_dict_in_list(
        PROJECT_COSTS,
        "project_id",
        project_id
    )
    # Was it newly created?
    project_in_list.setdefault("project_id", project_id)
    # May have had project added by S3 processing so
    # check that we've got the pipeline structure.
    project_in_list.setdefault("pipelines", [])
    # Find the pipeline object
    pipeline_in_list = find_dict_in_list(
        project_in_list["pipelines"],
        "pipeline_id",
        pipeline_id
    )
    # Was it newly created?
    pipeline_in_list.setdefault("pipeline_id", pipeline_id)
    pipeline_in_list.setdefault("jobs", [])
    # Find the jobs object
    job_in_list = find_dict_in_list(
        pipeline_in_list["jobs"],
        "job_id",
        job_id
    )
    # Was it newly created?
    job_in_list.setdefault("job_id", job_id)
    job_in_list.setdefault("cost", 0.0)

    job_in_list["cost"] += cost
    TOTAL_ALLOCATED += cost


def job_times_for_slot(row: dict, job: dict) -> Tuple[Union[None, datetime.datetime], Union[None, datetime.datetime]]:
    """Get job start & end times, adjusted for the current hour being worked on

    Args:
        row (dict): a row from the CUR file
        job (dict): the job being processed

    Returns:
        Tuple[Union[None, datetime.datetime], Union[None, datetime.datetime]]: the start and end times, or None if
        they are outside the start & end time for the CUR file row being processed.
    """
    row_start = dateutil_parser.isoparse(row[USAGE_START_DATE])
    row_end = dateutil_parser.isoparse(row["lineItem/UsageEndDate"])

    job_start = job["job_start"]
    job_end = job["job_end"]

    if job_start > row_end:
        job_start = None
    elif job_start < row_start:
        job_start = row_start

    if job_end < row_start:
        job_end = None
    elif job_end > row_end:
        job_end = row_end

    return job_start, job_end


def add_project_build_cost(job_data: list, row: dict, source: str):
    """Add this row's costs to the specified project/build(s)

    Args:
        job_data (list): a list of one or more jobs associated with this cost
        row (dict): CUR file row
        source (str): EC2, networking, storage, etc.
    """
    if row[LINE_ITEM_ID] == "":
        return

    blended_cost = float(row[UNBLENDED_COST])
    if len(job_data) > 1:
        # Need to apportion the cost based on the usage time for each
        # of the jobs.
        job_time = []
        for job in job_data:
            job_start, job_end = job_times_for_slot(row, job)
            if job_start is not None and job_end is not None:
                job_time.append(job_end - job_start)

        overall_time = sum(job_time, start=datetime.timedelta(0))

        if job_data != [] and overall_time != 0.0:
            output(
                f"{len(job_data)} jobs to process for {source} with overall time {overall_time}", LogLevel.DEBUG)
            job_cost_sum = 0.0
            for job in job_data:
                job_start, job_end = job_times_for_slot(row, job)
                if job_start is not None and job_end is not None:
                    time_spent = job_end - job_start
                    job_cost = blended_cost * time_spent / overall_time
                    add_cost_to_project(
                        job["project_id"], job["pipeline_id"], job["job_id"], job_cost)
                    job_cost_sum += job_cost
            # The * / calculations can, over enough calculations, cause a rounding difference.
            # We'll add any difference detected between job_cost_sum and blended_cost to
            # the first job (safest approach as we know it exists).
            #
            # We're talking really small amounts of money so, overall, it doesn't make
            # any difference - it is just to shut up the safety net logic elsewhere in
            # the script.
            difference = blended_cost - job_cost_sum
            add_cost_to_project(
                job_data[0]["project_id"],
                job_data[0]["pipeline_id"],
                job_data[0]["job_id"],
                difference
            )
        else:
            # This *shouldn't* happen. For a given resource, if there was a runner on it,
            # we ought to be processing some jobs.
            output(
                f"No jobs being checked for {row[RESOURCE_ID]}", LogLevel.ERROR)
    else:
        # Only one job on this instance so they pay for everything
        add_cost_to_project(
            job_data[0]["project_id"], job_data[0]["pipeline_id"], job_data[0]["job_id"], blended_cost)
    processed_this_row(row)


def process_pending_instance_costs(start_time: str):
    """Allocate EC2 instance, volume & network costs to projects & builds

    Args:
        start_time (str): the time block of costs to process
    """
    job_data = extract_job_data(PENDING_INSTANCE_COSTS, start_time)

    for instance in PENDING_INSTANCE_COSTS[start_time]:
        resource_id = instance[RESOURCE_ID]
        if len(job_data[resource_id]) != 0:
            add_project_build_cost(job_data[resource_id], instance, "instance")
        else:
            # This node didn't have any runners
            output(
                f"Adding instance costs for {resource_id} to base (no runners)", LogLevel.DEBUG)
            add_to(BASE_COSTS, instance)
        check_volume_costs(resource_id, job_data[resource_id])
        check_network_costs(resource_id, job_data[resource_id])


def check_volume_costs(resource_id: str, job_data: list):
    """Find the volume attached to the instance and add that cost

    Args:
        resource_id (str): resource ID to find associated volume(s)
        job_data (list): jobs that ran on this instance
    """
    # As with network costs, it is possible for the CUR to have volume costs in an hour where
    # the instance apparently not running ... so don't fixate on the precise timeslot.
    for key in PENDING_VOLUME_COSTS:
        for volume in PENDING_VOLUME_COSTS[key]:
            # Match on the resource ID and make sure it hasn't been processed already
            if volume[INSTANCE_ID] == resource_id:
                if len(job_data) != 0:
                    add_project_build_cost(job_data, volume, "volume")
                else:
                    output(
                        f"Adding volume costs for {resource_id} to base (no runners)", LogLevel.DEBUG)
                    add_to(BASE_COSTS, volume)


def check_network_costs(resource_id: str, job_data: list):
    """Find any network costs ... but only add them to the project costs once.

    Args:
        resource_id (str): resource ID to find associated network costs
        job_data (list): jobs that ran on this instance
    """
    # It is possible for the CUR to have network costs in an hour where the instance is
    # apparently NOT running so we have to look beyond the precise timeslot where the
    # instance was charged.
    for key in PENDING_EC2NW_COSTS:
        for nw in PENDING_EC2NW_COSTS[key]:
            # Match on the resource ID and make sure it hasn't been processed already
            if nw[RESOURCE_ID] == resource_id:
                if len(job_data) != 0:
                    add_project_build_cost(job_data, nw, "network")
                else:
                    output(
                        f"Adding network costs for {resource_id} to base (no runners)", LogLevel.DEBUG)
                    add_to(BASE_COSTS, nw)


def process_pending_ec2nw_costs(start_time: str):
    """Process any EC2 network costs that were generated by the nodes in the default node group

    Args:
        start_time (str): the time block of costs to process
    """
    for nw in PENDING_EC2NW_COSTS[start_time]:
        if nw[RESOURCE_ID] in DEFAULT_NODE_INSTANCES:
            add_to(BASE_COSTS, nw)


def process_pending_fargate_costs(start_time: str, network_total_cost: float, nat_gateway: Union[str, None]) -> float:
    """Allocate network costs to projects based on their NAT gateway usage proportion

    Args:
        start_time (str): the time block to process
        network_total_cost (float): the original total cost to divvy up
        nat_gateway (Union[str, None]): the NAT gateway ID or None if we didn't find one

    Returns:
        float: cost if not allocated or 0.0 if allocated to Fargate jobs
    """
    job_data = extract_job_data(PENDING_FARGATE_COSTS, start_time)

    project_network_usage = {}
    total_bytes = 0

    # Iterate through each build that took place (i.e. each pod) to see
    # how much NAT traffic it generated or received.
    for proj in PENDING_FARGATE_COSTS[start_time]:
        resource_id = proj[RESOURCE_ID]
        add_project_build_cost(job_data[resource_id], proj, "Fargate")
        if nat_gateway is not None:
            total_bytes += calculate_network_usage(
                nat_gateway, project_network_usage, proj, job_data)

    # If there was no traffic through the NAT gateway then we can't allocate any of the cost.
    if total_bytes == 0:
        return network_total_cost

    # If there have been data transfer costs but it hasn't been possible to get the IP address
    # (e.g. because the costs were incurred before logging was set up) then we may be in a
    # situation where we cannot reallocate those costs across the projects. In which case, we'll
    # have to add them back to the base costs AND GET THE LOGGING FIXED!
    if len(project_network_usage) == 0:
        output(
            f"Unable to allocate Fargate network costs to projects for {start_time}",
            LogLevel.ERROR)
        return network_total_cost

    for project in project_network_usage:
        for pipeline in project_network_usage[project]:
            for job in project_network_usage[project][pipeline]:
                perc = project_network_usage[project][pipeline][job] * \
                    100.0 / total_bytes
                output(
                    f"Job {project}/{pipeline}/{job} used {perc:.2f}% of the NAT traffic", LogLevel.INFO)
                cost = (network_total_cost * perc / 100.0)
                add_cost_to_project(project, pipeline, job, cost)

    # The network cost has been shared out across the various Fargate projects, so nothing left
    # to add to the base cost.
    return 0.0


def add_project_network_usage(usage_dict: dict, project_id: str, pipeline_id: str, job_id: str, bytes_used: int):
    """Add up the network usage, creating dicts as required

    Args:
        usage_dict (dict): network usage dictionary
        project_id (str): project ID
        pipeline_id (str): pipeline ID
        job_id (str): job ID
        bytes_used (int): bytes used by this job
    """
    usage_dict.setdefault(project_id, {})
    usage_dict[project_id].setdefault(pipeline_id, {})
    usage_dict[project_id][pipeline_id].setdefault(job_id, 0.0)
    usage_dict[project_id][pipeline_id][job_id] += bytes_used


def calculate_network_usage(nat_gateway: str, project_network_usage: dict, proj: dict, job_data: dict) -> int:
    """Work out how much NAT traffic was generated by this job

    Args:
        nat_gateway (str): NAT gateway to check
        project_network_usage (dict): network usage tracking dictionary
        proj (dict): CUR row
        job_data (dict): job data to check

    Returns:
        int: bytes used by this job
    """
    if "DataTransfer-Regional-Bytes" not in proj[USAGE_TYPE]:
        return 0

    bytes_used = 0

    resource_id = proj[RESOURCE_ID]
    for job in job_data[resource_id]:
        project_id = job["project_id"]
        pipeline_id = job["pipeline_id"]
        job_id = job["job_id"]
        pod_name = job["pod_name"]
        pod_start = job["pod_start"]
        pod_end = job["pod_end"]

        ip_address = get_ip_for_pod(pod_name, pod_start, pod_end)
        if ip_address is not None:
            records = get_nat_traffic(
                nat_gateway, ip_address, pod_start, pod_end)
            project_bytes = add_up_traffic(records)
            add_project_network_usage(
                project_network_usage,
                project_id,
                pipeline_id,
                job_id,
                project_bytes
            )
            bytes_used += project_bytes

    return bytes_used


def add_up_traffic(records: list) -> int:
    """Add up all of the VPC flow log traffic

    Args:
        records (list): list of VPC flog log records

    Returns:
        int: total bytes processed
    """
    project_bytes = 0
    for rec in records:
        this_bytes = value_from_cloudwatch_log(rec, "bytes")
        if this_bytes is not None:
            project_bytes += int(this_bytes)
    return project_bytes


def process_cur_report(s3_bucket: str, s3_key: str):
    """Process the records in the specified file

    Args:
        s3_bucket (str): S3 bucket to retrieve file from
        s3_key (str): Key for S3 file to read
    """
    global TOTAL_COST_FROM_CUR, CUR_FILE_ROW_COUNT

    s3 = boto3.client('s3')
    response = s3.get_object(Bucket=s3_bucket, Key=s3_key)
    gzipped = GzipFile(None, 'rb', fileobj=response['Body'])
    data = TextIOWrapper(gzipped)  # type: ignore
    reader = csv.DictReader(data)
    for row in reader:
        if DEBUG:
            CUR_FILE.append(row)
        code = row[PRODUCT_CODE]
        # There are lots of different line item types but only three
        # relates to usage chargess
        if "Usage" not in row["lineItem/LineItemType"]:
            process_base_cost(row)
        elif code in EXPECTED_BASED_COSTS:
            process_base_cost(row)
        elif code == "AmazonEC2":
            process_ec2(row)
        elif code == "AmazonEKS":
            process_eks(row)
        elif code == "AmazonS3":
            process_s3(row)
        else:
            add_to(UNALLOCATED_COSTS, row)
        CUR_FILE_ROW_COUNT += 1
        TOTAL_COST_FROM_CUR += float(row[UNBLENDED_COST])
    check_pending_volumes()
    output(
        f"Sanity check: rows counted = {CUR_FILE_ROW_COUNT}, size of list = {len(CUR_FILE)}", LogLevel.DEBUG)


def check_pending_volumes():
    """ Check the pending volumes to see if any are for a code node """
    global PENDING_VOLUME_COSTS
    new_pending_volumes = {}
    for key in PENDING_VOLUME_COSTS:
        for volume in PENDING_VOLUME_COSTS[key]:
            if volume_in_nodegroup(volume):
                add_to(BASE_COSTS, volume)
            elif INSTANCE_ID in volume and volume[INSTANCE_ID] == "":
                # We have a volume but no instance ID to help link to an instance
                add_to(UNALLOCATED_COSTS, volume)
            else:
                append_to(new_pending_volumes, volume)
    PENDING_VOLUME_COSTS = new_pending_volumes


def volume_in_nodegroup(row):
    """ Is this an EC2 volume belonging to a nodegroup? """
    if row[PRODUCT_CODE] != "AmazonEC2" or \
            "EBS:VolumeUsage" not in row[USAGE_TYPE]:
        return False

    for group in DEFAULT_NODE_GROUPS:
        if row[USER_NAME_TAG] == group:
            return True

    return False


def add_to(cost_dict: dict, row: dict, key: Union[None, str]=None):
    """Add the cost from row to the specified cost dict, keyed by date

    Args:
        cost_dict (dict): one of the cost dicts to add the cost to
        row (dict): CUR file row to process
        key (str, optional): Key to store the value under. Defaults to None, in which case
            a default key is constructed based off values from the CUR file row.
    """
    # Sanity-check that we haven't added this row already ...
    if row[LINE_ITEM_ID] == "":
        return

    processed_this_row(row)
    # Ignore zero costs ...
    if float(row[UNBLENDED_COST]) == 0.0:
        return
    if key is None:
        key = row[PRODUCT_CODE] + "/" + row[USAGE_TYPE]
        if row[USAGE_TYPE] == "":
            key += row["lineItem/LineItemType"]
    cost = float(row[UNBLENDED_COST])
    add_cost_to_dict(cost_dict, row[USAGE_START_DATE], key, cost)  # type: ignore


def add_cost_to_dict(cost_dict: dict, date_time_str: str, key: str, cost: float):
    """Add the cost to the dictionary

    Args:
        cost_dict (dict): one of the cost dictionaries
        date_time_str (str): date/time string so that we can extract the date
        key (str): what to store this cost under
        cost (float): the cost to be stored
    """
    cost_date = date_time_str.split("T")[0]
    ensure_dict_cost_keys_exist(cost_date, key, cost_dict)
    cost_dict[cost_date][key] += cost


def append_to(pending_dict: dict, row: dict):
    """Add this row to the specified dict, keyed by usage start date

    Args:
        pending_dict (dict): one of the PENDING dictionaries
        row (dict): the CUR file row to add to the dictionary
    """
    usage_start_date = row[USAGE_START_DATE]
    pending_dict.setdefault(usage_start_date, [])
    pending_dict[usage_start_date].append(row)
    if usage_start_date not in USAGE_START_KEYS:
        USAGE_START_KEYS.append(usage_start_date)


def process_ec2(row: dict):
    """Process an EC2 cost from the CUR file

    Args:
        row (dict): CUR file row to be processed
    """
    # Apart from NAT gateway hours, any other costs will depend on which EC2
    # instance caused the costs.
    #
    # If the instance is part of the "default" nodegroup then that is a base
    # cost (including its volume).
    #
    # Otherwise, it is likely/going to be an instance running a CI job so
    # we then need to figure out *which* job.
    #
    # Uses "in code" rather than explicit string comparisons because AWS
    # prepends region codes if the activity is anywhere other than us-east-1.

    code = row[USAGE_TYPE]
    if "NatGateway-Hours" in code:
        # NAT gateway hours are a base cost as it has to run all of the time.
        add_to(BASE_COSTS, row)
    elif "EBS:VolumeUsage" in code:
        process_ec2_volume(row)
    elif "BoxUsage:" in code:
        process_ec2_instance(row)
    elif ":natgateway/nat-" in row[RESOURCE_ID]:
        append_to(PENDING_NATGW_COSTS, row)
        if DEBUG_NATGW_COSTS:
            row[UNBLENDED_COST] = 0.0
    else:
        append_to(PENDING_EC2NW_COSTS, row)
        if DEBUG_EC2NW_COSTS:
            row[UNBLENDED_COST] = 0.0


def process_ec2_volume(row: dict):
    """Add a volume cost to PENDING for later processing

    Args:
        row (dict): CUR file row
    """
    # For all volumes, add them to pending for now. Once we've collected all of the EC2
    # information, we'll go through the list and allocate those that belong to the core
    # nodegroup instances to the base costs.
    append_to(PENDING_VOLUME_COSTS, row)
    if DEBUG_VOLUME_COSTS:
        row[UNBLENDED_COST] = 0.0


def process_ec2_instance(row: dict):
    """Process an EC2 instance cost

    Args:
        row (dict): CUR file row
    """
    # Keep track of ALL EC2 instance IDs
    if row[RESOURCE_ID] not in EC2_INSTANCE_IDS:
        EC2_INSTANCE_IDS.append(row[RESOURCE_ID])

    if USER_NAME_TAG in row:
        # See if this was created by Karpenter. If it was, treat
        # it as a Node instance.
        name = row[USER_NAME_TAG]
        if len(name) > len(PROVISIONER_NAME) and \
                name[:len(PROVISIONER_NAME)] == PROVISIONER_NAME:
            # It must be a Node EC2 instance so hold it for now.
            append_to(PENDING_INSTANCE_COSTS, row)
            if DEBUG_INSTANCE_COSTS:
                row[UNBLENDED_COST] = 0.0
            return

    # Otherwise, assume it is a base node. We can't make that decision based
    # on the node group name because it could be something other than "default".
    #
    # Remember which nodes make up the default nodegroup so that
    # any EC2 traffic costs associated with those nodes can be
    # added to the base costs.
    if row[RESOURCE_ID] not in DEFAULT_NODE_INSTANCES:
        DEFAULT_NODE_INSTANCES.append(row[RESOURCE_ID])
    if row[USER_NAME_TAG] not in DEFAULT_NODE_GROUPS:
        DEFAULT_NODE_GROUPS.append(row[USER_NAME_TAG])
    add_to(BASE_COSTS, row)


def process_eks(row: dict):
    """Process an EKS cost row

    Args:
        row (dict): CUR file row
    """
    if row["lineItem/Operation"] != "FargatePod":
        add_to(BASE_COSTS, row)
        return

    project_id = project_id_from_fargate_id(row[RESOURCE_ID])
    if project_id is None:
        # Not a project pod
        add_to(UNALLOCATED_COSTS, row, resource_id_key(row))
        return

    # Keep all of the Fargate costs back for now.
    append_to(PENDING_FARGATE_COSTS, row)
    if DEBUG_FARGATE_COSTS:
        row[UNBLENDED_COST] = 0.0


def process_s3(row: dict):
    """Process the S3 costs

    Args:
        row (dict): CUR file row
    """
    # From a practical perspective, the only S3 costs that can fairly be
    # apportioned to each GitLab project is the storage costs. There are
    # underlying "requests" costs but (a) they are quite small and (b) it
    # doesn't seem to be feasible to associate them with a given project.
    if row[RESOURCE_ID] == CACHE_BUCKET and \
            row[USAGE_TYPE] == "TimedStorage-ByteHrs":
        process_s3_storage_costs(row)
    else:
        add_to(BASE_COSTS, row, key=resource_id_key(row))


def process_base_cost(row: dict):
    """Process this cost as a base cost

    Args:
        row (dict): CUR file row
    """
    add_to(BASE_COSTS, row)


def ec2_node_details(resource_id: str, pod_start: datetime.datetime, pod_end: datetime.datetime) -> list:
    """Determine the project ID, build ID and pod name via the resource ID

    Args:
        resource_id (str): EC2 instance ID
        pod_start (datetime.datetime): when do we want to start looking?
        pod_end (datetime.datetime): when do we want to stop looking?

    Returns:
        list: list of jobs that ran on this instance
    """
    # Start by getting the host name for this instance ID
    hostname = ec2_node_hostname(resource_id, pod_start, pod_end)
    if hostname is not None:
        # Having got the hostname, find the log entry for when the runner pod gets
        # created.
        runner_list = get_runner_name(hostname, pod_start, pod_end)
    else:
        runner_list = []
    # Don't need to explcitly check for not knowing the hostname as
    # that will initialise runner_list to be empty and therefore trigger
    # this next bit.
    if runner_list is None or len(runner_list) == 0:
        return [
            {
                "project_id": None,
                "pipeline_id": None,
                "job_id": None,
                "pod_name": None,
                "pod_start": pod_start,
                "pod_end": pod_end
            }
        ]

    response = []
    fetch_job_times = (len(runner_list) > 1)
    for runner in runner_list:
        parts = runner.split("project-")
        project_id = parts[1].split("-")[0]
        pipeline_id, job_id = ci_ids_from_runner_logs(
            runner, pod_start, pod_end)
        if fetch_job_times and job_id is not None:
            job_start, job_end = fetch_job_times_from_gitlab(
                project_id, job_id)
        else:
            job_start = None
            job_end = None
        response.append(
            {
                "project_id": project_id,
                "pipeline_id": pipeline_id,
                "job_id": job_id,
                "pod_name": runner,
                "pod_start": pod_start,
                "pod_end": pod_end,
                "job_start": job_start,
                "job_end": job_end
            }
        )
    return response


def fetch_job_times_from_gitlab(project_id: str, job_id: str) -> Tuple[datetime.datetime, datetime.datetime]:
    """Get the CI job start & end times back from GitLab

    Args:
        project_id (str): project ID
        job_id (str): job ID

    Returns:
        Tuple[datetime.datetime, datetime.datetime]: start and end times for this job
    """
    # Call the jobs API to retrieve data like:
    # created_at: "2022-11-01T00:03:18.932Z"
    # started_at: "2022-11-01T00:03:27.140Z"
    # finished_at: "2022-11-01T00:06:00.834Z"
    gitlab_job = f"projects/{project_id}/jobs/{job_id}"
    found, data = get_data_from_cache(
        "gitlab_jobs", gitlab_job, None, None)
    if not found or data is None:
        output(f"Fetching job times for '{gitlab_job}'", LogLevel.DEBUG)
        header = {
            "PRIVATE-TOKEN": GITLAB_TOKEN
        }
        response = requests.get(
            f"{GITLAB_URL}api/v4/projects/{project_id}/jobs/{job_id}",
            headers=header
        )
        response.raise_for_status()
        data = response.json()
        save_data_to_cache(
            "gitlab_jobs", gitlab_job, None, None,
            {"started_at": data["started_at"],
                "finished_at": data["finished_at"]}
        )
    started_at = data["started_at"]
    finished_at = data["finished_at"]
    return dateutil_parser.isoparse(started_at), dateutil_parser.isoparse(finished_at)


def get_data_from_cache(type: str, identifier: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[bool, Union[None, Type]]:
    """Retrieve data from the general purpose analysis cache

    Args:
        type (str): what sort of data are we retrieving, e.g. gitlab_jobs, ci_ids, runner_name
        identifier (str): key to retrieve the value
        start_time (Union[datetime.datetime, None]): optional start time to preserve as well
        end_time (Union[datetime.datetime, None]): optional end time to preserve as well

    Returns:
        Tuple[bool, Union[None, Type]]: did we find it and, if so, the data retrieved
    """
    if type not in ANALYSIS_CACHE:
        return False, None
    # datetime isn't serializable by JSON so we store it as a string
    enc_start = None if start_time is None else start_time.isoformat()
    end_end = None if end_time is None else end_time.isoformat()
    for values in ANALYSIS_CACHE[type]:
        if values["id"] == identifier and \
            values["start_time"] == enc_start and \
                values["end_time"] == end_end:
            return True, values["data"]
    return False, None


def save_data_to_cache(type: str, identifier: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None], data: Union[None, str, dict, list]):
    """Save the data to the cache

    Args:
        type (str): the bucket of data being stored, e.g. gitlab_jobs, ci_ids, runner_name
        identifier (str): the key to store this value under
        start_time (Union[datetime.datetime, None]): optional - store the start time as well
        end_time (Union[datetime.datetime, None]): optional - store the end time as well
        data (Union[None, str, dict, list]): the data to be stored
    """
    ANALYSIS_CACHE.setdefault(type, [])
    # Check that the result isn't there already - it shouldn't be
    found, _ = get_data_from_cache(type, identifier, start_time, end_time)
    if found:
        return
    # datetime isn't serializable by JSON so we store it as a string
    enc_start = None if start_time is None else start_time.isoformat()
    end_end = None if end_time is None else end_time.isoformat()
    ANALYSIS_CACHE[type].append(
        {
            "id": identifier,
            "start_time": enc_start,
            "end_time": end_end,
            "data": data
        }
    )


def get_runner_name_from_cache(ec2_hostname: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[bool, Union[None, list]]:
    """Try to find the runner name in the cache

    Args:
        ec2_hostname (str): EC2 hostname to match against
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time

    Returns:
        Tuple[bool, Union[None, list]]: did we find it and, if we did, what was the answer?
    """
    return get_data_from_cache("ec2_runner_name", ec2_hostname, start_time, end_time)


def save_runner_name_to_cache(ec2_hostname: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None], runner_name: list):
    """Save the runner name in the cache

    Args:
        ec2_hostname (str): EC2 hostname for this runner name
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time
        runner_name (list): runner that ran on this instance
    """
    save_data_to_cache("ec2_runner_name", ec2_hostname,
                       start_time, end_time, runner_name)


def get_runner_name(ec2_hostname: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Union[None, list]:
    """Find the log entry for the runner pod getting created

    Args:
        ec2_hostname (str): the EC2 host that we want to find a runner for
        start_time (Union[datetime.datetime, None]): check from this time ...
        end_time (Union[datetime.datetime, None]): ... to this time

    Returns:
        Union[None, list]: a list of one or more runners or None if there weren't any
    """
    found, runner_name = get_runner_name_from_cache(
        ec2_hostname, start_time, end_time)
    if found:
        return runner_name

    if start_time is not None and end_time is not None and CW_CLUSTER_LOGS is not None:
        start_time, end_time = sanity_check_query_times(
            CW_CLUSTER_LOGS, start_time, end_time)
    if start_time is None or end_time is None:
        output(
            f"Start/end time to query {CW_CLUSTER_LOGS} for runner name for {ec2_hostname} is out of range",
            LogLevel.WARNING)
        save_runner_name_to_cache(ec2_hostname, start_time, end_time, [])
        return []

    query_string = (
        "fields objectRef.namespace, objectRef.name"
        f"| filter requestObject.target.name like \"{ec2_hostname}\""
        f"| filter objectRef.name like /runner/"
        f"| filter verb like \"create\""
    )
    client = boto3.client('logs')
    response = client.start_query(
        logGroupName=CW_CLUSTER_LOGS,
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=query_string
    )
    query_id = response["queryId"]
    results = get_results_from_cloudwatch_query(client, query_id)
    response = []
    for result in results:
        name = value_from_cloudwatch_log(result, "objectRef.name")
        response.append(name)
    if len(response) == 0:
        output(
            f"No runner nodes found for {ec2_hostname}, {start_time} -> {end_time}",
            LogLevel.DEBUG)
    save_runner_name_to_cache(ec2_hostname, start_time, end_time, response)
    return response


def get_ec2_hostname_from_cache(resource_id: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[bool, Union[None, str]]:
    """Try to find the hostname name in the cache

    Args:
        resource_id (str): resource ID from CUR file
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time

    Returns:
        Tuple[bool, Union[None, str]]: did we find it and, if we did, what was the answer?
    """
    return get_data_from_cache("ec2_hostname", resource_id, start_time, end_time)


def save_ec2_hostname_to_cache(resource_id: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None], hostname: Union[str, None]):
    """Save the runner name in the cache

    Args:
        resource_id (str): resource ID from CUR file
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time
        hostname (Union[str, None]): the hostname to remember
    """
    save_data_to_cache("ec2_hostname", resource_id,
                       start_time, end_time, hostname)


def ec2_node_hostname(resource_id: str, start_time: datetime.datetime, end_time: datetime.datetime) -> Union[None, str]:
    """Use the cluster logs to find the hostname for this instance

    Args:
        resource_id (str): the resource ID to look for
        start_time (datetime.datetime): search from this time ...
        end_time (datetime.datetime): ... to this time

    Returns:
        Union[None, str]: hostname if found or None if not
    """
    found, hostname = get_ec2_hostname_from_cache(
        resource_id, start_time, end_time)
    if found:
        return hostname

    hostname = None
    query_string = (
        "fields @timestamp, user.username"
        f"| filter user.extra.sessionName.0 like \"{resource_id}\""
        "| sort @timestamp asc"
        "| limit 1"
    )
    client = boto3.client('logs')
    response = client.start_query(
        logGroupName=CW_CLUSTER_LOGS,
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=query_string
    )
    query_id = response["queryId"]
    results = get_results_from_cloudwatch_query(client, query_id)
    for entry in results:
        username = value_from_cloudwatch_log(entry, "user.username")
        if username is not None:
            # Returns something like system:node:ip-192-168-25-115.ap-southeast-1.compute.internal
            parts = username.split(":")
            if len(parts) > 2:
                hostname = parts[2]
                break

    if hostname is None:
        output(
            f"Cannot determine hostname for {resource_id}, {start_time} -> {end_time}",
            LogLevel.WARNING)

    save_ec2_hostname_to_cache(resource_id, start_time, end_time, hostname)
    return hostname


def get_results_from_cloudwatch_query(cw_client, query_id: str) -> list:
    """Wait for CW Logs to finish the query & return the results

    Args:
        cw_client (boto3 client): CloudWatch Logs client instance
        query_id (str): the query being performed

    Returns:
        list: the results found or an empty list
    """
    status = "Scheduled"
    while status in ["Scheduled", "Running"]:
        response = cw_client.get_query_results(queryId=query_id)
        status = response["status"]
        if status == "Complete":
            return response["results"]
        # Sleep for a bit to avoid hitting AWS threshold
        time.sleep(5)

    return []


def project_id_from_fargate_id(resource_id: str) -> Union[None, str]:
    """Extract project ID from the Fargate resource ID

    Args:
        resource_id (str): EKS resource ID

    Returns:
        Union[None, str]: the project ID from the resource ID or None if it isn't a project resource
    """
    # e.g. arn:aws:eks:us-east-1:AWS-ACCOUNT-ID:pod/EKS-CLUSTER-NAME/EKS-FARGATE-NAMESPACE/runner-agwxvf7b-project-5-concurrent-0j9nvc/319228f6-6d46-4bb5-910e-a4ed39927b6c
    parts = resource_id.split("project-")
    if len(parts) != 2:
        # This shouldn't happen ...
        return None
    return parts[1].split("-")[0]


def fargate_pod_details(resource_id: str, pod_start: datetime.datetime, pod_end: datetime.datetime) -> list:
    """Determine the project ID, build ID and pod name via the resource ID

    Args:
        resource_id (str): pod resource ID
        pod_start (datetime.datetime): search from this time ...
        pod_end (datetime.datetime): ... to this time

    Returns:
        list: all of the job details as a single-element list (to be compatible with the EC2 results)
    """
    project_id = project_id_from_fargate_id(resource_id)
    if project_id is None:
        project_id = None
        pipeline_id = None
        job_id = None
        pod_name = None
    else:
        parts = resource_id.split("/")
        pod_name = parts[3]
        pipeline_id, job_id = ci_ids_from_runner_logs(
            pod_name, pod_start, pod_end)
    response = [
        {
            "project_id": project_id,
            "pipeline_id": pipeline_id,
            "job_id": job_id,
            "pod_name": pod_name,
            "pod_start": pod_start,
            "pod_end": pod_end
        }
    ]
    return response


def get_ci_ids_from_cache(runner_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[bool, Union[None, str], Union[None, str]]:
    """Try to find the CI IDs in the cache

    Args:
        runner_name (str): runner name
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time

    Returns:
        Tuple[bool, Union[None, str], Union[None, str]]: did we find the results and, if we did, what were the pipeline & job IDs?
    """
    found, data = get_data_from_cache(
        "ci_ids", runner_name, start_time, end_time)
    if found and data is not None:
        return True, data["pipeline_id"], data["job_id"]
    return False, "", ""


def save_ci_ids_to_cache(runner_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None], pipeline_id: Union[str, None], job_id: Union[str, None]):
    """Save the CI IDs in the cache

    Args:
        runner_name (str): runner name to store the data under
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time
        pipeline_id (Union[str, None]): pipeline ID to save
        job_id (Union[str, None]): job ID to save
    """
    save_data_to_cache("ci_ids", runner_name, start_time,
                       end_time, {"pipeline_id": pipeline_id, "job_id": job_id})


def ci_ids_from_runner_logs(runner_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[Union[None, str], Union[None, str]]:
    """Scan GitLab Runner logs for this build

    Args:
        runner_name (str): runner name
        start_time (Union[datetime.datetime, None]): search from this time ...
        end_time (Union[datetime.datetime, None]): ... to this time

    Returns:
        Tuple[Union[None, str], Union[None, str]]: pipeline ID and job ID
    """
    found, pipeline_id, job_id = get_ci_ids_from_cache(
        runner_name, start_time, end_time)
    if found:
        return pipeline_id, job_id

    if CW_CLUSTER_LOGS is not None and start_time is not None and end_time is not None:
        start_time, end_time = sanity_check_query_times(
            CW_CLUSTER_LOGS, start_time, end_time)
    if start_time is None or end_time is None:
        output(
            f"Start/end time to query {CW_CLUSTER_LOGS} for job ID for {runner_name} is out of range",
            LogLevel.WARNING)
        save_ci_ids_to_cache(runner_name, start_time, end_time, None, None)
        return None, None

    job_id = None
    pipeline_id = None

    query_string = (
        "fields requestObject.metadata.labels.job_id, requestObject.metadata.labels.pipeline_id"
        f"| filter responseObject.metadata.name like \"{runner_name}\""
        "| filter verb like \"create\""
    )

    client = boto3.client('logs')
    response = client.start_query(
        logGroupName=CW_CLUSTER_LOGS,
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=query_string
    )
    query_id = response["queryId"]
    results = get_results_from_cloudwatch_query(client, query_id)
    for result in results:
        job_id_value = value_from_cloudwatch_log(
            result, "requestObject.metadata.labels.job_id")
        pipeline_id_value = value_from_cloudwatch_log(
            result, "requestObject.metadata.labels.pipeline_id")
        if job_id_value is not None and pipeline_id_value is not None:
            job_id = job_id_value
            pipeline_id = pipeline_id_value
            break

    if job_id is None or pipeline_id is None:
        output(
            f"Cannot determine job/pipeline IDs for {runner_name}, {start_time} -> {end_time}",
            LogLevel.WARNING)
    save_ci_ids_to_cache(runner_name, start_time,
                         end_time, pipeline_id, job_id)
    return pipeline_id, job_id


def resource_id_key(row: dict, middle_key: str = USAGE_TYPE) -> str:
    """Creates cost key that includes resource ID

    Args:
        row (dict): CUR file row
        middle_key (str, optional): What to add to the cost key. Defaults to USAGE_TYPE.

    Returns:
        str: cost key to use
    """
    key = row[PRODUCT_CODE] + "/" + row[middle_key]
    if row[RESOURCE_ID] != "":
        key += "/" + row[RESOURCE_ID]
    return key


def extract_nat_gateway(resource_id: str) -> Union[None, str]:
    """Get the NAT gateway ID from the resource ID

    Args:
        resource_id (str): resource ID from CUR file

    Returns:
        Union[None, str]: NAT gateway ID or None if not a NAT gateway
    """
    parts = resource_id.split("natgateway/")
    if len(parts) != 2:
        return None  # not a NAT gateway
    return parts[1]


def sanity_check_query_times(log_group: str, start_time: datetime.datetime, end_time: datetime.datetime) -> Tuple[Union[None, datetime.datetime], Union[None, datetime.datetime]]:
    """Make sure start_time & end_time are valid for this group

    Args:
        log_group (str): log group we are going to query
        start_time (datetime.datetime): when we want to start the query
        end_time (datetime.datetime): when we want to end the query

    Returns:
        Tuple[Union[None, datetime.datetime], Union[None, datetime.datetime]]: start & end times, None if not valid, revised if needed
    """
    # If start_time and end_time are before the creation of the group, return None.
    # If start_time and end_time are more than X days previous, where X is the group's
    #   retention period, return None.
    # If start_time < creation of the group, adjust start_time to be the creation of the group.
    #
    # Note that all of the CloudWatch queries require the timestamps to be seconds since the Epoch but
    # describe_log_groups has values in milliseconds so we start by multiplying the start and end times.
    start_timestamp = start_time.timestamp() * 1000
    end_timestamp = end_time.timestamp() * 1000

    client = boto3.client('logs')
    response = client.describe_log_groups(
        logGroupNamePrefix=log_group
    )

    for group in response["logGroups"]:
        if group["logGroupName"] == log_group:
            creation_time = int(group["creationTime"])
            if start_timestamp < creation_time and end_timestamp < creation_time:
                return None, None
            # Calculate the earliest possible log date/time given the retention period.
            retention = datetime.datetime.now(
            ) - datetime.timedelta(days=group["retentionInDays"])
            retention = int(retention.timestamp()) * 1000
            if start_timestamp < retention and end_timestamp < retention:
                return None, None
            if start_timestamp < creation_time:
                start_time = datetime.datetime.fromtimestamp(creation_time/1000.0)
            break

    return start_time, end_time


def get_pod_ip_from_cache(pod_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Tuple[bool, Union[None, str]]:
    """Try to find the pod IP address in the cache

    Args:
        pod_name (str): pod name
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time

    Returns:
        Tuple[bool, Union[None, str]]: did we find it and, if we did, what was the IP address?
    """
    return get_data_from_cache("pod_ip", pod_name, start_time, end_time)


def save_pod_ip_to_cache(pod_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None], ip_address: Union[str, None]):
    """Save the pod IP address in the cache

    Args:
        pod_name (str): pod name
        start_time (Union[datetime.datetime, None]): start time
        end_time (Union[datetime.datetime, None]): end time
        ip_address (Union[str, None]): IP address to save
    """
    save_data_to_cache("pod_ip", pod_name, start_time, end_time, ip_address)


def get_ip_for_pod(pod_name: str, start_time: Union[datetime.datetime, None], end_time: Union[datetime.datetime, None]) -> Union[None, str]:
    """Query the CloudWatch logs to retrieve the associated IP address

    Args:
        pod_name (str): pod name
        start_time (Union[datetime.datetime, None]): search from this time ...
        end_time (Union[datetime.datetime, None]): ... to this time

    Returns:
        Union[None, str]: IP address or None if not found
    """
    found, ip_address = get_pod_ip_from_cache(pod_name, start_time, end_time)
    if found:
        return ip_address

    if CW_CLUSTER_LOGS is not None and start_time is not None and end_time is not None:
        start_time, end_time = sanity_check_query_times(
            CW_CLUSTER_LOGS, start_time, end_time)
    if start_time is None or end_time is None:
        output(
            f"Start/end time to query {CW_CLUSTER_LOGS} for IP address for {pod_name} is out of range",
            LogLevel.WARNING)
        return None

    ip_address = None
    client = boto3.client('logs')
    response = client.start_query(
        logGroupName=CW_CLUSTER_LOGS,
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=(
            "fields requestObject.status.podIP"
            " | filter @logStream like /^kube-apiserver-audit/"
            f" | filter objectRef.name = \"{pod_name}\""
            " | filter verb like \"patch\""
            " | sort @timestamp desc"
        )
    )
    query_id = response["queryId"]
    results = get_results_from_cloudwatch_query(client, query_id)
    # We will get multiple results back from this query. We just need one
    # that tells us what the IP address is.
    #
    # Previously, the query filter included a clause to check for
    # requestObject.status.initContainerStatuses.0.ready = 1. However, for
    # short-lived pods, by the time the pod reports ready, it may have
    # finished running and no longer have the IP address. So now we look
    # for the IP address being reported in any result.
    for result in results:
        ip_address = value_from_cloudwatch_log(
            result, "requestObject.status.podIP")
        if ip_address is not None:
            break
    if ip_address is None:
        output(
            f"Warning! Unable to determine IP address for pod {pod_name}, {start_time} -> {end_time}",
            LogLevel.WARNING)
    save_pod_ip_to_cache(pod_name, start_time, end_time, ip_address)
    return ip_address


def value_from_cloudwatch_log(dict_of_values: dict, key_name: str) -> Union[str, None]:
    """Find the specified key and return its value

    Args:
        dict_of_values (dict): results from the Logs query
        key_name (str): key that we are looking for

    Returns:
        Union[str, None]: the value for that key, or None if not there
    """
    for result in dict_of_values:
        if result["field"] == key_name:
            return result["value"]
    return None


def get_nat_traffic(nat_id: str, ip_address: str, start_time: datetime.datetime, end_time: datetime.datetime) -> "list[dict]":
    """Get flow records for the gateway + IP address combo

    Args:
        nat_id (str): NAT gateway ID
        ip_address (str): IP address to search for
        start_time (datetime.datetime): search from this time ...
        end_time (datetime.datetime): ... to this time

    Returns:
        list[dict]: flow records that we've discovered
    """
    # Get the ENI for the NAT gateway
    client = boto3.client("ec2")
    response = client.describe_nat_gateways(
        NatGatewayIds=[nat_id]
    )
    eni = response["NatGateways"][0]["NatGatewayAddresses"][0]["NetworkInterfaceId"]

    query_string = (
        "fields @timestamp, @message"
        f" | filter @logStream = \"{eni}-accept\""
        "| parse @message \"* * * * * * * * * * *\" as bytes, dstAddr, srcAddr, pktDstaddr, pktSrcaddr, logStatus, instanceId, pktSrcAwsService, pktDstAwsService, flowDirection, trafficPath"
        f" | filter srcAddr = \"{ip_address}\" or dstAddr = \"{ip_address}\""
        " | sort @timestamp desc"
    )
    client = boto3.client('logs')
    response = client.start_query(
        logGroupName=CW_VPC_FLOW_LOGS,
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=query_string
    )
    query_id = response["queryId"]
    return get_results_from_cloudwatch_query(client, query_id)


def process_s3_storage_costs(row: dict):
    """Add up the storage, apportion to each project & save costs

    Args:
        row (dict): CUR file row
    """
    global TOTAL_ALLOCATED
    cache_cost = float(row[UNBLENDED_COST])
    project_cache_usage = {}
    total_cache_usage = 0
    # Work out how much storage is being used per project
    s3 = boto3.resource("s3")
    bucket = s3.Bucket(CACHE_BUCKET)  # type: ignore
    files = bucket.objects.all()
    for file in files:
        output(f"S3 cache: {file.key} = {file.size} bytes", LogLevel.INFO)
        parts = file.key.split("/")
        project = parts[2]
        size = int(file.size)
        total_cache_usage += size
        if project in project_cache_usage:
            project_cache_usage[project] += size
        else:
            project_cache_usage[project] = size
    # Calculate the percentage used and allocate the cost
    for proj in project_cache_usage:
        perc = project_cache_usage[proj] * 100.0 / total_cache_usage
        output(
            f"Project {proj} using {perc:.2f}% of the S3 cache bucket", LogLevel.INFO)
        project_in_list = find_dict_in_list(
            PROJECT_COSTS,
            "project_id",
            proj
        )
        if "project_id" not in project_in_list:
            project_in_list["project_id"] = proj
        if "cache_cost" not in project_in_list:
            project_in_list["cache_cost"] = 0.0
        cost = (cache_cost * perc / 100.0)
        project_in_list["cache_cost"] += cost
        TOTAL_ALLOCATED += cost
    processed_this_row(row)


if __name__ == "__main__":
    perform_billing_analysis()
