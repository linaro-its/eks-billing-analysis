#!/bin/sh
export AWS_DEFAULT_REGION="ap-southeast-1"
export CACHE_BUCKET_NAME="ci-dev-cache-codelinaro-org"
export CUR_BUCKET_NAME="consolidated-billing-cur-linaro-org"
export CUR_PREFIX="sbsl_curs/cur1"
export ASSUME_CUR_READING_ROLE="arn:aws:iam::967448898940:role/CurBucketAccessRole"
export RESULTS_BUCKET_NAME="ci-dev-billing-codelinaro-org"

export CW_CLUSTER_LOGS="/aws/eks/ci-cluster/cluster"
export CW_VPC_FLOW_LOGS="vpc-flow-logs"

export AUTH0_CLIENT_AUDIENCE="https://api.codelinaro.org/v1/"
export AUTH0_CLIENT_URL="https://staging-auth.codelinaro.org/oauth/token"
export CLO_API_URL="https://staging-api.codelinaro.org/v1"
export GITLAB_URL="https://staging-git.codelinaro.org/"
export SECRET_NAME="eks-billing-analysis-auth0"

export OVERRIDE_SAVE_ALREADY_SAVED="True"

# Use -u to unbuffer the output so that it appears in the logs promptly
python -u billing_analysis.py
