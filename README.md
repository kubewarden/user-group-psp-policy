# Kubewarden policy user-group-psp

This Kubewarden Policy is a replacement for the Kubernetes Pod Security
Policy that controls containers [user and groups](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups).

This policy is used to control users and groups in containers.

## Settings


The policy has three settings:

* `run_as_user`: Controls which user ID the containers are run with. As well as the user in the securityContext from PodSpec.
* `run_as_group`:  Controls which primary group ID the containers are run with. As well as the group in the securityContext from PodSpec.
* `supplemental_groups`: Controls which group IDs containers add.

All three settings have no defaults, just like the deprecated PSP (also, they would get used if `mutating` is `true`).

All three settings are JSON objects composed by three attributes: `rule`, `ranges` and `overwrite`. The `rule` attribute defines
the strategy used by the policy to enforce users and groups used in containers. The available strategies are:

* `run_as_user`:
	* `MustRunAs` - Requires at least one range to be specified. Uses the minimum value of the first range as the default. Validates against all ranges.
	* `MustRunAsNonRoot` - Requires that the pod be submitted with a non-zero `runAsUser` or have the `USER` directive defined (using a numeric UID) in the image. Pods which have specified neither `runAsNonRoot` nor `runAsUser` settings will be mutated to set `runAsNonRoot=true`, thus requiring a defined non-zero numeric `USER` directive in the container. No default provided.
	* `RunAsAny` - No default provided. Allows any `runAsUser` to be specified.
* `run_as_group`:
	* `MustRunAs` - Requires at least one range to be specified. Uses the minimum value of the first range as the default. Validates against all ranges.
	* `MayRunAs` - Does not require that `RunAsGroup` be specified. However, when `RunAsGroup` is specified, they have to fall in the defined range.
	* `RunAsAny` - No default provided. Allows any `runAsGroup` to be specified.
* `supplemental_groups`:
	* `MustRunAs` - Requires at least one range to be specified. Uses the minimum value of the first range as the default. Validates against all ranges.
	* `MayRunAs` - Requires at least one range to be specified. Allows `supplementalGroups` to be left unset without providing a default. Validates against all ranges if `supplementalGroups` is set.
	* `RunAsAny` - No default provided. Allows any `supplementalGroups` to be specified

The `ranges` is a list of JSON objects with two attributes: `min` and `max`. Each range object define the user/group ID range used by the rule.

`overwrite` attribute can be set `true` only with the rule `MustRunAs`. This flag configure the policy to mutate the `runAsUser` or `runAsGroup` despite of the value present in the
request. Even if the value is a valid one. The default value of this attribute is `false`.

This policy can inspect Pod resources, but can also operate against "higher order"
Kubernetes resources like Deployment, ReplicaSet, DaemonSet, ReplicationController,
Job and CronJob.

It's up to the operator to decide which kind of resources the policy is going to inspect.
That is done when declaring the policy.

There are pros and cons to both approaches:

- Have the policy inspect low level resources, like Pod. Different kind of Kubernetes
  resources (be them native or CRDs) can create Pods. By having the policy target Pod
  objects, there's the guarantee all the Pods are going to be compliant. However,
  this could lead to some confusion among end users of the cluster: their high level
  Kubernetes resources would be successfully created, but they would stay in a non
  reconciled state. For example, a Deployment creating a non-compliant Pod would be
  created, but it would never have all its replicas running. The end user would
  have to do some debugging to finally understand why this is happening.
- Have the policy inspect higher order resource (e.g. Deployment): the end users
  will get immediate feedback about the rejections. However, there's still the
  chance that some non compliant pods are created by another high level resource
  (be it native to Kubernetes, or a CRD).



### Examples

To enforce that user and groups must be set and it should be in the defined ranges:

```json
{
  "run_as_user": {
    "rule": "MustRunAs",
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      },
      {
        "min": 3000,
        "max": 3999
      }
    ]
  },
  "run_as_group": {
    "rule": "MustRunAs",
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      },
      {
        "min": 3000,
        "max": 3999
      }
    ]
  },
  "supplemental_groups":{
    "rule": "MustRunAs",
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      },
      {
        "min": 3000,
        "max": 3999
      }
    ]
  }
}
```

To allow any user and group:

```json
{
  "run_as_user": {
    "rule": "RunAsAny"
  },
  "run_as_group": {
    "rule": "RunAsAny"
  },
  "supplemental_groups":{
    "rule": "RunAsAny"
  }
}
```

To force running the container with non root user but any group:

```json
{
  "run_as_user": {
    "rule": "MustRunAsNonRoot"
  },
  "run_as_group": {
    "rule": "RunAsAny"
  },
  "supplemental_groups":{
    "rule": "RunAsAny"
  }
}
```

To enforce a group when the container has some group defined

```json
{
  "run_as_user": {
    "rule": "RunAsAny"
  },
  "run_as_group": {
    "rule": "MayRunAs",
    "ranges": [
      {
        "min": 1000,
        "max": 2000
      },
      {
        "min": 2001,
        "max": 3000
      }
    ]
  },
  "supplemental_groups":{
    "rule": "MayRunAs",
    "ranges": [
      {
        "min": 1000,
        "max": 2000
      },
      {
        "min": 2001,
        "max": 3000
      }
    ]
  }
}
```

To enforce that user and groups will be the defined one in the policy configuration,
set `overwrite` as `true`:

```json
{
  "run_as_user": {
    "rule": "MustRunAs",
    "overwrite": true,
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      }
    ]
  },
  "run_as_group": {
    "rule": "MustRunAs",
    "overwrite": true,
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      },
    ]
  },
  "supplemental_groups":{
    "rule": "MustRunAs",
    "overwrite": true,
    "ranges": [
      {
        "min": 1000,
        "max": 1999
      },
    ]
  }
}
```
