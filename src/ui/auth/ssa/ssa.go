// Copyright (c) 2017 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssa

import (
	"github.com/vmware/harbor/src/common/dao"
	"github.com/vmware/harbor/src/common/models"
	"github.com/vmware/harbor/src/ui/auth"
	"net/http"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
)


// jd erp data
type ERP_DATA struct {

	UserId int

	Fullname string

	Email string

	Mobile string

	PersonId string

	OrgId string

	OrgName string

	HrmDeptId string

	Expire int

	Username string

}

// jd erp
type ERP struct {
	REQ_DATA ERP_DATA

	REQ_FLAG bool

	REQ_CODE int

	REQ_MSG string
}

// Auth implements Authenticator interface to authenticate user against DB.
type Auth struct {
	auth.DefaultAuthenticateHelper
}

// Authenticate calls dao to authenticate user.
func (d *Auth) Authenticate(m models.AuthModel) (*models.User, error) {

	// verify
	hasher := md5.New()
	hasher.Write([]byte(m.Password))
	password := hex.EncodeToString(hasher.Sum(nil))

	url := "http://ssa.jd.com/sso/verify?username=" + m.Principal + "&password=" + password

	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()

	var erp ERP
	json.NewDecoder(res.Body).Decode(&erp)

	if erp.REQ_FLAG {
		erp_data := erp.REQ_DATA

		u := models.User{
			Username: erp_data.Username,
			Email: erp_data.Email,
			Realname: erp_data.Fullname,
			Comment: "From JD SSA",
		}

		// save to local db
		var queryCondition = models.User{
			Username: erp_data.Username,
		}

		isExist, _ := dao.UserExists(queryCondition,  "username")
		if !isExist {
			dao.OnBoardUser(&u)
		}

		return &u, nil
	} else {
		return nil, auth.NewErrAuth("Invalid credentials")
	}
}

// SearchUser - Check if user exist in local db
func (d *Auth) SearchUser(username string) (*models.User, error) {
	var queryCondition = models.User{
		Username: username,
	}

	return dao.GetUser(queryCondition)
}

// OnBoardUser -
func (d *Auth) OnBoardUser(u *models.User) error {
	return nil
}

func init() {
	auth.Register("jd_ssa", &Auth{})
}
