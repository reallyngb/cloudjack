{
  "users": {
    "intern": {
      "name": "intern",
      "arn": "arn:aws:iam::123456789012:user/intern",
      "inline_policies": {
        "intern-policy": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": null,
              "Effect": "Allow",
              "Action": [
                "iam:AttachUserPolicy"
              ],
              "NotAction": null,
              "Resource": [
                "*"
              ],
              "NotResource": null,
              "Condition": null,
              "Principal": null
            },
            {
              "Sid": null,
              "Effect": "Allow",
              "Action": [
                "s3:GetObject"
              ],
              "NotAction": null,
              "Resource": [
                "arn:aws:s3:::public-data/*"
              ],
              "NotResource": null,
              "Condition": null,
              "Principal": null
            }
          ]
        }
      },
      "managed_policies": []
    },
    "admin": {
      "name": "admin",
      "arn": "arn:aws:iam::123456789012:user/admin",
      "inline_policies": {},
      "managed_policies": [
        {
          "Version": "2012-10-17",
          "Statement": {
            "Sid": null,
            "Effect": "Deny",
            "Action": [
              "*"
            ],
            "NotAction": null,
            "Resource": [
              "*"
            ],
            "NotResource": null,
            "Condition": null,
            "Principal": null
          }
        }
      ]
    }
  },
  "roles": {},
  "resources": {
    "prod-data": {
      "name": "prod-data",
      "arn": "arn:aws:s3:::prod-data",
      "type": "S3Bucket",
      "sensitivity": 5
    }
  }
}