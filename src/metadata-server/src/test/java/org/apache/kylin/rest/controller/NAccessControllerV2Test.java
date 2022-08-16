/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kylin.rest.controller;

import static org.apache.kylin.common.constant.HttpConstant.HTTP_VND_APACHE_KYLIN_V2_JSON;

import org.apache.kylin.rest.constant.Constant;
import org.apache.kylin.rest.service.AccessService;
import org.apache.kylin.rest.service.UserService;
import org.apache.kylin.rest.controller.v2.NAccessControllerV2;
import org.apache.kylin.rest.service.AclTCRService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.google.common.collect.Lists;

public class NAccessControllerV2Test {

    private MockMvc mockMvc;

    @Mock
    private AccessService accessService;

    @Mock
    private UserService userService;

    @Mock
    private AclTCRService aclTCRService;

    @InjectMocks
    private NAccessControllerV2 nAccessControllerV2 = Mockito.spy(new NAccessControllerV2());

    private final Authentication authentication = new TestingAuthenticationToken("ADMIN", "ADMIN", Constant.ROLE_ADMIN);

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        mockMvc = MockMvcBuilders.standaloneSetup(nAccessControllerV2) //
                .defaultRequest(MockMvcRequestBuilders.get("/")).build();

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testGetAllAccessEntitiesOfUser() throws Exception {
        String userName = "ADMIN";
        Mockito.when(accessService.getGrantedProjectsOfUser(userName)).thenReturn(Lists.newArrayList("default"));
        Mockito.when(userService.userExists(userName)).thenReturn(Boolean.TRUE);
        Mockito.when(aclTCRService.getAuthorizedTables("default", userName)).thenReturn(Lists.newArrayList());

        mockMvc.perform(MockMvcRequestBuilders.get("/api/access/{userName:.+}", userName)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.parseMediaType(HTTP_VND_APACHE_KYLIN_V2_JSON)))
                .andExpect(MockMvcResultMatchers.status().isOk()).andReturn();

        Mockito.verify(nAccessControllerV2).getAllAccessEntitiesOfUser(userName);
    }

}
