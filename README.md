# TrustedASMPolicies

\*\*iControlLX extension to export ASM policies from and import onto trusted devices

The process of exporting ASM policies from BIG-IPs where they are authored and then importing them on enforcement devices has multiple steps and is complex. This extension provides a simplified user experience for querying, exporting, importing, and deleting ASM policies on trusted devices.

## Building the Extension

The repository includes the ability to simply run

`npm run-script build`

in the repository root folder. In order for this run-script to work, you will need to be on a linux workstation with the `rpmbuild` utility installed.

Alternatively rpm builds can be downloaded from the releases tab on github.

## Installing the Extension

The installation instructions for iControlLX rpm packages are found here:

[Installing iControlLX Extensions](https://clouddocs.f5.com/products/iapp/iapp-lx/docker-1_0_4/icontrollx_pacakges/working_with_icontrollx_packages.html)

This extension has been tested on TMOS version 13.1.1 and the [API Service Gateway](https://hub.docker.com/r/f5devcentral/f5-api-services-gateway/) container.

## General Control Parameters

This extension extends the iControl REST URI namespace at:

`/mgmt/shared/TrustedASMPolicies`

There are three main operations available.

### GET Requests

GET requests follow the common TrustedDevice syntax and take the following parameters:

| Parameter    | Value                                                        |
| ------------ | ------------------------------------------------------------ |
| `targetHost` | The trusted device host or if not supplied the local device. |
| `targetUUID` | The trusted device UUID or if not supplied the local device. |
| `policyName` | The name of the ASM policy you want to query.                |
| `policyUUID` | The UUID of the ASM policy you want to query.                |

You can supply `targetHost` or `targetUUID`. If you supply `targetUUID` the `targetHost` and `targetPort` will be resolved for you.

In addition you can specify the `targetUUID` as a path parameter to keep the user experience the same as the TrustProxy extension.

`/mgmt/shared/TrustedASMPolicies/7390b3b8-7682-4554-83e5-764e4f26703c`

If supplied as a path variable, the `targetUUD` does not need to send as a query variable.

The `policyName` query variable is optional and will filter the results to the first policy with name starting with the supplied `policyName` value.

The `policyUUID` query variable is optional and will filter the results to the policy with UUID matching the supplied `policyUUID` value.

In addition ou can specify the `policyUUID` as a path variable after the `targetUUID` in the path.

`/mgmt/shared/TrustedASMPolicies/7390b3b8-7682-4554-83e5-764e4f26703c/DkhEogaI2u5fwK_kKo5Ctw`

#### Query for all ASM policies on a trusted Device

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=172.13.1.106

```

#### Response

```bash
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "lastChanged": "2018-12-26T16:55:52Z",
        "lastChange:": "Security Policy /Common/linux-high [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-high, username = admin, client IP = 192.168.0.65 }",
        "state": "AVAILABLE",
        "path": "/Common/linux-high"
    },
    {
        "id": "HjoMjahFu2fw2_hft6toj",
        "name": "linux-medium",
        "enforcementMode": "blocking",
        "lastChanged": "2018-12-26T16:55:52Z",
        "lastChange:": "Security Policy /Common/linux-medium [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-medium, username = admin, client IP = 192.168.0.65 }",
        "state": "AVAILABLE",
        "path": "/Common/linux-medium"
    }
]
```

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee

```

#### Response

```bash
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "lastChanged": "2018-12-26T16:55:52Z",
        "lastChange:": "Security Policy /Common/linux-high [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-high, username = admin, client IP = 192.168.0.65 }",
        "state": "AVAILABLE",
        "path": "/Common/linux-high"
    },
    {
        "id": "HjoMjahFu2fw2_hft6toj",
        "name": "linux-medium",
        "enforcementMode": "blocking",
        "lastChanged": "2018-12-26T16:55:52Z",
        "lastChange:": "Security Policy /Common/linux-medium [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-medium, username = admin, client IP = 192.168.0.65 }",
        "state": "AVAILABLE",
        "path": "/Common/linux-medium"
    }
]
```

#### Query for an ASM by name or id on a trusted device

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=172.13.1.106&policyName=linux-high
```

#### Response

```bash
{
    "id": "DkhEogaI2u5fwK_kKo5Ctw",
    "name": "linux-high",
    "enforcementMode": "blocking",
    "lastChanged": "2018-12-26T16:55:52Z",
    "lastChange:": "Security Policy /Common/linux-high [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-high, username = admin, client IP = 192.168.0.65 }",
    "state": "AVAILABLE",
    "path": "/Common/linux-high"
}
```

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee/DkhEogaI2u5fwK_kKo5Ctw
```

#### Response

```bash
{
    "id": "DkhEogaI2u5fwK_kKo5Ctw",
    "name": "linux-high",
    "enforcementMode": "blocking",
    "lastChanged": "2018-12-26T16:55:52Z",
    "lastChange:": "Security Policy /Common/linux-high [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-high, username = admin, client IP = 192.168.0.65 }",
    "state": "AVAILABLE",
    "path": "/Common/linux-high"
}
```

### Retrieving an ASM XLM policy file from a trsuted source device

The `GET` method can also be used to retrieve an exported ASM policy as an XML file. To retrieve the exported ASM policy as an XML file you must supply the following variables:

| Parameter    | Value                                                               |
| ------------ | ------------------------------------------------------------------- |
| `sourceHost` | The trusted device host to export the ASM policy.                   |
| `sourceUUID` | The trusted device UUID to export the ASM policy.                   |
| `policyId`   | The ID of the ASM policy you want to delete from the target host.   |
| `policyName` | The name of the ASM policy you want to delete from the target host. |

You can supply either the `sourceHost` or `sourceUUID`.

You can supply either the `policyId` or `policyName`.

You MUST not supply a `targetHost` or `targetUUID`, as these will trigger a query for ASM policies on a device.

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?sourceHost=172.13.1.106&policyName=linux-high
```

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?sourceUUID=8c79ab99-fa76-4e6e-a03a-5610620e4fee&policyId=DkhEogaI2u5fwK_kKo5Ctw
```

### DELETE Requests

DELETE requests follow the common TrustedDevice syntax and take the following parameters:

| Parameter    | Value                                                               |
| ------------ | ------------------------------------------------------------------- |
| `targetHost` | The trusted device host or if not supplied the local device.        |
| `targetUUID` | The trusted device UUID or if not supplied the local device.        |
| `policyId`   | The ID of the ASM policy you want to delete from the target host.   |
| `policyName` | The name of the ASM policy you want to delete from the target host. |

You can supply `targetHost` or `targetUUID`. If you supply `targetUUID` the `targetHost` and `targetPort` will be resolved for you.

In addition you can specify the `targetUUID` as a path parameter to keep the user experience the same as the TrustProxy extension.

`/mgmt/shared/TrustedASMPolicies/7390b3b8-7682-4554-83e5-764e4f26703c`

If supplied as a path variable, the `targetUUD` does not need to send as a query variable.

You can supply either the `policyId` or the `policyName` query variable, but you must supply at least one fo these to specify policy to delete on the target device.

```bash
DELETE https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee?policyId=DkhEogaI2u5fwK_kKo5Ctw

```

#### Response

```bash
{
    "msg": "policy removed on target 172.13.1.106:443"
}
```

Additionally, in keeping with the TrustedProxy model, policies can also be deleted using only the URI path variables for both the trusted device UUID and the policy ID.

```bash
DELETE https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee/DkhEogaI2u5fwK_kKo5Ctw

```

Of course, policies can be deleted using `targetHost` IP address and `policyName` query variables.

```bash
DELETE https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=172.13.1.106&policyName=linux-high

```

#### Response

```bash
{
    "msg": "policy removed on target 172.13.1.106:443"
}
```

#### Response

```bash
{
    "msg": "policy removed on target 172.13.1.106:443"
}
```

### POST Requests

POST requests import ASM policies on a target trusted device. The source of the policy can either be exported from a different trusted device, or can be downloaded from a non-BIG-IP URL.

#### Exporting from a BIG-IP device

The source policy to be exported from a trusted device is specified us the following parameters:

| Parameter    | Value                                                                         |
| ------------ | ----------------------------------------------------------------------------- |
| `sourceHost` | The trusted device which currently has the policy to export.                  |
| `sourceUUID` | The trusted device UUID which currently has the policy to export.             |
| `policyId`   | The ID of the ASM policy you want to export from a source trusted device.     |
| `policyName` | The name of the ASM policy you want to export from the source trusted device. |

You can specify either the `sourceHost` or the `sourceUUID` to identify the source trusted device.

You can specify either the `policyId` or the `policyName` to identify the ASM policy to export.

The target device to import the policy is specified using the following parameters:

| Parameter          | Value                                                          |
| ------------------ | -------------------------------------------------------------- |
| `targetHost`       | The trusted device host or if not supplied the local device.   |
| `targetHosts`      | List of trusted device hosts to import the source policy.      |
| `targetUUID`       | The trusted device UUID or if not supplied the local device.   |
| `targetUUIDs`      | List of trusted device UUIDs to import the source policy.      |
| `targetPolicyName` | Required name for the policy on the target device.             |

These variables can be defined as either query variables or part of the `POST` body.

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies?sourceHost=172.13.1.101&targetHost=172.13.1.106&policyName=linux-high&targetPolicyName=imported-linux-high
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies?sourceHost=172.13.1.101&targetHosts=172.13.1.106,172.13.1.107,172.13.1.108&policyName=linux-high&targetPolicyName=imported-linux-high
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceHost": "172.13.1.101",
    "targetHost": "172.13.1.106",
    "policyName": "linux-high",
    "targetPolicyName": "imported-linux-high"
}
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceUUID": "b80652cb-20bd-4e81-a6a6-c306fd643af7",
    "targetUUID": "8c79ab99-fa76-4e6e-a03a-5610620e4fee",
    "policyId": "DkhEogaI2u5fwK_kKo5Ctw",
    "targetPolicyName": "imported-linux-high"
}
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceHost": "172.13.1.101",
    "targetHosts": ["172.13.1.106","172.13.1.107","172.13.1.108"]
    "policyName": "linux-high",
    "targetPolicyName": "imported-linux-high"
}
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceUUID": "b80652cb-20bd-4e81-a6a6-c306fd643af7",
    "targetUUIDs": ["8c79ab99-fa76-4e6e-a03a-5610620e4fee","92d0aa7c-a08e-41dd-a114-9192ae040f4c","415c9787-8513-4480-a037-f1f87c8a6851"],
    "policyId": "DkhEogaI2u5fwK_kKo5Ctw",
    "targetPolicyName": "imported-linux-high"
}
```

When the request is submitted, a returned policy status matching the `GET` request format is returned immediately. The process is asynchronous. There is a `state` attribute which can be quried using `GET` requests which should transition through the following states:

| `state` Value | Meaning                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------- |
| `REQUESTED`   | The process has been requested, but not initialized                                            |
| `EXPORTING`   | The policy is being exported from the source device                                            |
| `DOWNLOADING` | The exported policy is being downloaded from the source device                                 |
| `UPLOADING`   | The exported policy is being uploaded to the target device                                     |
| `IMPORTING`   | The policy is being imported on the target device                                              |
| `AVAILABLE`   | The policy has been applied on the target device                                               |
| `ERROR`       | An error has occurred during the process and the `restnoded` log should be checked for details |

#### Response

```bash
{
    "id": "DkhEogaI2u5fwK_kKo5Ctw",
    "name": "linux-high",
    "enforcementMode": "blocking",
    "state": "EXPORTING"
}
```

Query the current state

```bash
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=173.13.1.106&policyName=linux-high
```

#### Response

```bash
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "lastChanged": "2018-12-26T16:55:52Z",
        "lastChange:": "Security Policy /Common/linux-high [update]: Enforcement Mode was set to Blocking. { audit: policy = /Common/linux-high, username = admin, client IP = 192.168.0.65 }",
        "state": "UPLOADING",
        "path": "/Common/linux-high"
    }
]
```

#### Downloading from a non-BIG-IP URL

The source of the ASM policy can be downloaded from a non-BIG-IP URL using the following parameters:

| Parameter | Value                                                                                       |
| --------- | ------------------------------------------------------------------------------------------- |
| `url`     | The non-BIG-UP HTTP/HTTPS/FILE URL to download the previously exported ASM policy XML file. |

The target device to import the policy is specified using the following parameters:

| Parameter          | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| `targetHost`       | The trusted device host or if not supplied the local device. |
| `targetUUID`       | The trusted device UUID or if not supplied the local device. |
| `targetPolicyName` | The required name for the policy on the target device.       |

These variables can be defined as either query variables or part of the `POST` body.

The following requests are equivalent.

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies?url=https://raw.githubusercontent.com/f5devcentral/f5-asm-policy-template-v13/master/application_ready_template_v13/Drupal_8/Drupal_8_Ready_Template_6.1.2_v13.xml&targetHost=172.13.1.101&targetPolicyName=Drupal_8_Ready_Template
```

```bash
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "url": "https://raw.githubusercontent.com/f5devcentral/f5-asm-policy-template-v13/master/application_ready_template_v13/Drupal_8/Drupal_8_Ready_Template_6.1.2_v13.xml"
    "targetHost": "172.13.1.106",
    "targetPolicyName": "Drupal_8_Ready_Template"
}
```

The response is given in the same `GET` format, following the following states:

| `state` Value | Meaning                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------- |
| `REQUESTED`   | The process has been requested, but not initialized                                            |
| `DOWNLOADING` | The exported policy is being downloaded from the source device                                 |
| `UPLOADING`   | The exported policy is being uploaded to the target device                                     |
| `IMPORTING`   | The policy is being imported on the target device                                              |
| `AVAILABLE`   | The policy has been applied on the target device                                               |
| `ERROR`       | An error has occurred during the process and the `restnoded` log should be checked for details |
