# TrustedASMPolicies
**iControlLX extension to export ASM policies from and import onto trusted devices**

The process of exporting ASM policies from BIG-IPs where they are authored and then importing them on enforcement devices has multiple steps and is complex. This extension provides a simplified user experience for querying, exporting, importing, and deleting ASM policies on trusted devices.

## Building the Extension ##

The repository includes the ability to simply run 

`npm run-script build` 

in the repository root folder. In order for this run-script to work, you will need to be on a linux workstation with the `rpmbuild` utility installed.

Alternatively rpm builds can be downloaded from the releases tab on github.

## Installing the Extension ##

The installation instructions for iControlLX rpm packages are found here:

[Installing iControlLX Extensions](https://clouddocs.f5.com/products/iapp/iapp-lx/docker-1_0_4/icontrollx_pacakges/working_with_icontrollx_packages.html)

This extension has been tested on TMOS version 13.1.1 and the [API Service Gateway](https://hub.docker.com/r/f5devcentral/f5-api-services-gateway/) container.

## General Control Parameters ##

This extension extends the iControl REST URI namespace at:

`/mgmt/shared/TrustedASMPolicies`


There are three main operations available.

### GET Requests ###

GET requests follow the common TrustedDevice syntax and take the following parameters:


| Parameter | Value |
| --------- | ------ |
|`targetHost`| The trusted device host or if not supplied the local device
|`targetUUID`| The trusted device UUID or if not supplied the local device
|`policyName` | The name of the ASM policy you want to query

You can supply `targetHost` or `targetUUID`. If you supply `targetUUID` the `targetHost` and `targetPort` will be resolved for you.

In addition you can specify the `targetUUID` as a path parameter to keep the user experience the same as the TrustProxy extension.

`/mgmt/shared/TrustedASMPolicies/7390b3b8-7682-4554-83e5-764e4f26703c`

If supplied as a path variable, the `targetUUD` does not need to send as a query variable.

The `policyName` query variable is optional and will simply filter the results to policies with name starting with the supplied `policyName` value.

```
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=172.13.1.106

```

#### Response ####

```
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "state": "AVAILABLE",
        "path": "/Common/linux-high"
    },
    {
        "id": "HjoMjahFu2fw2_hft6toj",
        "name": "linux-medium",
        "enforcementMode": "blocking",
        "state": "AVAILABLE",
        "path": "/Common/linux-medium"
    }
]
```

```
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee

```

#### Response ####

```
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "state": "AVAILABLE",
        "path": "/Common/linux-high"
    },
    {
        "id": "HjoMjahFu2fw2_hft6toj",
        "name": "linux-medium",
        "enforcementMode": "blocking",
        "state": "AVAILABLE",
        "path": "/Common/linux-medium"
    }
]
```

### DELETE Requests ###

DELETE requests follow the common TrustedDevice syntax and take the following parameters:


| Parameter | Value |
| --------- | ------ |
|`targetHost`| The trusted device host or if not supplied the local device
|`targetUUID`| The trusted device UUID or if not supplied the local device
|`policyId` | The ID of the ASM policy you want to delete from the target host
|`policyName` | The name of the ASM policy you want to delete from the target host

You can supply `targetHost` or `targetUUID`. If you supply `targetUUID` the `targetHost` and `targetPort` will be resolved for you.

In addition you can specify the `targetUUID` as a path parameter to keep the user experience the same as the TrustProxy extension.

`/mgmt/shared/TrustedASMPolicies/7390b3b8-7682-4554-83e5-764e4f26703c`

If supplied as a path variable, the `targetUUD` does not need to send as a query variable.

You can supply either the `policyId` or the `policyName` query variable, but you must supply at least one fo these to specify policy to delete on the target device.

```
DELETE https://172.13.1.103/mgmt/shared/TrustedASMPolicies/8c79ab99-fa76-4e6e-a03a-5610620e4fee?policyId=DkhEogaI2u5fwK_kKo5Ctw

```

#### Response ####

```
{
    "msg": "policy removed on target 172.13.1.106:443"
}
```

```
DELETE https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=172.13.1.106&policyName=linux-high

```

#### Response ####

```
{
    "msg": "policy removed on target 172.13.1.106:443"
}
```

### POST Requests ###

POST requests require the specification of two different device, the source and the target, and the `policyId` or `policyName` attributes which specifies the ASM policy to export and download from the source device and then to upload, import, and apply on the target device. When specifying the source and target devices, you can use either the trusted device host or UUID. 


| Parameter | Value |
| --------- | ------ |
|`sourceHost`| The trusted device which currently has the policy to export
|`sourceUUID`| The trusted device UUID which currently has the policy to export
|`targetHost`| The trusted device host or if not supplied the local device
|`targetUUID`| The trusted device UUID or if not supplied the local device
|`policyId` | The ID of the ASM policy you want to delete from the target host
|`policyName` | The name of the ASM policy you want to delete from the target host


You can specify these parametes as either query variables or as part of the request body. The following request are equivalent:

```
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies?sourceHost=172.13.1.101&targetHost=172.13.1.106&policyName=linux-high
```

```
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceHost": "172.13.1.101",
    "targetHost": "172.13.1.106",
    "policyName": "linux-high"
}
```

```
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceUUID": "b80652cb-20bd-4e81-a6a6-c306fd643af7",
    "targetUUID": "8c79ab99-fa76-4e6e-a03a-5610620e4fee",
    "policyName": "linux-high"
}
```

When the request is submitted, a returned policy status matching the `GET` request format is returned immediately. The process is asynchronous. There is a `state` attribute which can be quried using `GET` requests which should transition through the following states:

| `state` Value | Meaning |
| --------- | ------ |
|`REQUESTED`| The process has been requested, but not initialized
|`EXPORTING`| The policy is being exported from the source device
|`DOWNLOADING`| The exported policy is being downloaded from the source device
|`UPLOADING`| The exported policy is being uploaded to the target device
|`IMPORTING` | The policy is being imported on the target device
|`AVAILABLE` | The policy has been applied on the target device
|`ERROR` | An error has occurred during the process and the `restnoded` log should be checked for details

```
POST https://172.13.1.103/mgmt/shared/TrustedASMPolicies

{
    "sourceHost": "172.13.1.101",
    "targetHost": "172.13.1.106",
    "policyName": "linux-high"
}
```

#### Response ####

```
{
    "id": "DkhEogaI2u5fwK_kKo5Ctw",
    "name": "linux-high",
    "enforcementMode": "blocking",
    "state": "EXPORTING"
}
```

Query the current state

```
GET https://172.13.1.103/mgmt/shared/TrustedASMPolicies?targetHost=173.13.1.106&policyName=linux-high
```

#### Response ####

```
[
    {
        "id": "DkhEogaI2u5fwK_kKo5Ctw",
        "name": "linux-high",
        "enforcementMode": "blocking",
        "state": "UPLOADING",
        "path": "/Common/linux-high"
    }
]
```
