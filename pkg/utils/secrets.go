/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/json"
	"errors"
	"k8s.io/api/core/v1"
)

func ExtractAuthFromSecret(secret *v1.Secret) ([]byte, error) {
	switch secret.Type {
	case "kubernetes.io/dockercfg":
		return secret.Data[".dockercfg"], nil
	case "kubernetes.io/dockerconfigjson":
		var objmap map[string]json.RawMessage
		if err := json.Unmarshal(secret.Data[".dockerconfigjson"], &objmap); err != nil {
			return nil, err
		}
		return objmap["auths"], nil
	}
	return nil, errors.New("unknown secret type")
}
