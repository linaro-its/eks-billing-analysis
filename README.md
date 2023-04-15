# EKS Billing Analysis

The EKS Billing Analysis script looks at Cost & Usage Reports for this month and last month and breaks down the AWS infrastructure costs to apportion them to specific GitLab projects/pipelines/jobs or to base costs. The script can operate on a "pass-through" basis or it can use a price list based on the number of CPUs used. A sample price list JSON file is in this repo. The price list **must** quote prices based on per-hour usage, just as AWS does.

The script is packaged into a Docker container and then configured as a Kubernetes cron job, running on one of the permanent nodes in the infrastructure.

## Setting up

Create a S3 bucket to store the results from the billing script.

### CodeLinaro setup

In the same region as the EKS cluster, create a secret (e.g. `eks-billing-analysis`) with values for `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET_KEY`, `GITLAB_TOKEN`, `PRICE_LIST`.

### Template file setup

It is necessary to set up an access policy to allow the script, while running in the EKS cluster, to access various other parts of the infrastructure.

There are two template files - `templates/ci-access-policy-cross-account.json` and `templates/ci-access-policy/same-account.json`. The names should indicate which one is needed, depending on whether you are accessing the CUR files from a different account or the same account.

Copy the desired template to the root directory and provide the values for the CUR bucket name, the CI cache bucket name and the billing results bucket name. If not running for CodeLinaro, the block that allows "secretsmanager" actions can be deleted, otherwise the ARN for the secret needs to be provided.

If using the cross-account template, it is necessary to create a role in the account holding the CUR that grants access when the role is assumed:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::CUR BUCKET/*",
                "arn:aws:s3:::CUR BUCKET"
            ]
        }
    ]
}
```

The role needs a trust relationship allowing it to be assumed by the account(s) where the script will be run:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::ACCOUNT NUMBER:root"
                ]
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
```

### ci.sh setup

Copy `templates/ci.sh` to the `container` directory and provide values for the first four `export` statements. If the EKS cluster has *not* been called `ci-cluster`, amend the value for `CW_CLUSTER_LOGS` accordingly.

## Create access policy

An access policy needs to be created that grants permissions required by the script:

```
aws iam create-policy --policy-name ci_access_policy --policy-document file://ci-access-policy.json
```

With the EKS cluster in place, it is then necessary to associate the access policy with a Kubernetes service account:

```
eksctl create iamserviceaccount \
                --name eks-billing-serviceaccount \
                --namespace default \
                --cluster ci-cluster \
                --attach-policy-arn arn:aws:iam::ACCOUNT NUMBER:policy/ci_access_policy \
                --approve
```

Note: if your EKS cluster is *not* called `ci-cluster`, the command must be amended appropriately.

Note: the account number is missing from the command above. Ensure that the full ARN for the policy is provided.

The container image is built by going into the `container` directory and running a command like the following:

```
docker build -t eks-billing-analysis:<version> .
```

where `version` is an incrementing value that is then referenced in `job.yaml` or `cron-job.yaml` to ensure the correct version of the image is used.

Once built, the image needs to be uploaded to a private ECR registry. Create a private registry in ECR called `eks-billing-analysis` and then follow the AWS-provided steps to upload the image to that registry, remembering to specify the version number in the tag and not `latest`.

Note that, when building the container, instead of a simple tag like `eks-billing-analysis:<version>`, the full AWS tag can be used, thus avoiding the need to re-tag before publishing to ECR.

The container references in `job.yaml` and/or `cron-job.yaml` will need to be updated to reflect the location of the registry.

## Deployment

## Billing Analyis Process

As noted above, the Python script is set up to be run once a day. When run, the script looks at the files it has generated already.

If there is a report for last month, the script looks to see if a CUR file has been added since that file was generated. If there was, the whole file is processed and last month's report is updated.

The latest CUR file for this month is also processed in its entirety. This avoids the complexities of trying to figure out what has changed between CUR files.

Regardless of which file is being processed, the script works by reading a line at a time from the CSV-format CUR file. Each row is either added to the base cost, the unallocated cost or marked as pending. Once all of the data has been processed once, the pending data is then processed on an hour-by-hour basis.

## Configuration

There are some values that need to be defined:

* RESULTS_BUCKET_NAME. This is the name of the S3 bucket where the reports are stored.

* CUR_BUCKET_NAME. This is the name of the S3 bucket where the CUR files are being stored.

* CUR_PREFIX. The path that comes before the date portion of the CUR file name.

* CACHE_BUCKET_NAME. This is the name of the S3 bucket used for the GitLab CI cache.

* CW_VPC_FLOW_LOGS. The CloudWatch logs group for VPC flow logs.

* CW_CLUSTER_LOGS. The CloudWatch logs group for the EKS Fargate cluster.

* ASSUME_ROLE. Optional: the name of the role to assume before accessing the CUR S3 bucket. If this is NOT an empty string, the script will assume that a consolidated billing CUR is being used and will filter the contents of the report based on the value of `lineItem/UsageAccountId` matching the account where the script is being run.

The script itself has two values to alter whether or not debugging is being done, and whether or not warnings should be suppressed or displayed.

## Karpenter Configuration

If Karpenter is being used to launch/terminate EC2 instances to provide more scale options than Fargate alone, it is necessary for the AWSNodeTemplate configuration in the Provisioner to have this `userData` section:

```
  userData: |
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="BOUNDARY"

    --BOUNDARY
    Content-Type: text/x-shellscript; charset="us-ascii"

    #!/bin/bash -xe
    exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
    TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
    AWS_AVAIL_ZONE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -S http://169.254.169.254/latest/meta-data/placement/availability-zone)
    AWS_REGION="`echo \"$AWS_AVAIL_ZONE\" | sed 's/[a-z]$//'`"
    AWS_INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -S http://169.254.169.254/latest/meta-data/instance-id)
    ROOT_VOLUME_IDS=$(aws ec2 describe-instances --region $AWS_REGION --instance-id $AWS_INSTANCE_ID --output text --query Reservations[0].I
nstances[0].BlockDeviceMappings[0].Ebs.VolumeId)
    aws ec2 create-tags --resources $ROOT_VOLUME_IDS --region $AWS_REGION --tags Key="InstanceID",Value="$AWS_INSTANCE_ID"

    --BOUNDARY--
```

The purpose of this is to ensure that the root volume for each newly-launched instance is tagged with the instance ID. This will allow the billing script to figure out which volume goes with which instance, and therefore the total cost.

## Cost Allocation Tag Configuration

In order for the Cost & Usage Report to contain all of the information needed by the script, it is necessary to activate some user-defined cost allocation tags.

If you are using consolidated billing, go to the Billing section of the bill-paying AWS account, otherwise go to the Billing section for the AWS account where the cluster is running.

Then click on *Cost allocation tags* on the left hand side and activate the following tags:

* InstanceID
* eks:nodegroup-name

If these tags are not found, it may be necessary to run some CI jobs in order for the tags to be detected.
