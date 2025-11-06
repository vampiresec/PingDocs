
Documentation: [OGNL Rerfernece](https://commons.apache.org/dormant/commons-ognl/language-guide.html)

### 1. Fetch Group CN values from groups array
```C
#groupCnOnly = new java.util.ArrayList(),
#groups = #this.get("memberOf")!=null ? #this.get("memberOf").getValues() : {},
#groups.{   
  #group = #this,   
  #group = new javax.naming.ldap.LdapName(#group),   
  #cn = #group.getRdn(#group.size() - 1).getValue().toString(),
  #groupCnOnly.add(#cn)
},
#this.get("memberOf")!=null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(#groupCnOnly):""
```
### 2. Filter Group CN Based on group name (case insensitive)
```C
#groupCnOnly = new java.util.ArrayList(),
#groups = #this.get("memberOf")!=null ? #this.get("memberOf").getValues() : {},
#groups.{   
  #group = #this,   
  #group = new javax.naming.ldap.LdapName(#group),   
  #cn = #group.getRdn(#group.size() - 1).getValue().toString(),
  #cn.matches("(?i)<group name>")?#groupCnOnly.add(#cn):" "
},
 
#this.get("memberOf")!=null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(#groupCnOnly):""
```
### 3. Binary data into readable format ObjectGUID
```C
#GUID = #this.get("ds.AD.objectGUID").toString(),  "{" + #GUID.substring(6,8) + #GUID.substring(4,6) + #GUID.substring(2,4) + #GUID.substring(0,2) + "-" +  #GUID.substring(10,12) + #GUID.substring(8,10) + "-" +  #GUID.substring(14,16) + #GUID.substring(12,14) + "-" +  #GUID.substring(16,20) + "-" + #GUID.substring(20,32) + "}"
```

### 4. Passing `access_token` in SAML Assertion
```C
#attrs = new java.util.HashMap(),#attrs.put("Subject",this.get("mail")),#attrs.put("Email",#this.get("mail")),#attrs.put("First Name",#this.get("givenName")),
#attrs.put("Last Name",#this.get("sn")),#attrs.put("COUNTRY",#this.get("country")),#attrs.put("Roles",#this.get("memberOf")),#val = @com.pingidentity.sdk.oauth20.AccessTokenIssuer@issueToken(#attrs,"","<Client Name>")
```
### 5. Passing roles based on group membership
```C
#roles = new java.util.ArrayList(),
#groups = #this.get("memberOf")!=null? #this.get("memberOf").getValues(),
#groups.{
    #this.toString().matches("(?i)Group1")?#roles.add("Role1"),
    #this.toString().matches("(?i)Group2")?#roles.add("Role2")
},
#this.get("memberOf")!=null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(#roles):""
```

### 6. Issuance criteria based on groups
```C
#this.get("ds.AD.memberOf")!=null?#this.get("ds.AD.memberOf").toString().matches("(?i).*<Group1>.*|.*<Group2>.*"):@java.lang.Boolean@FALSE
```

### 7. Issuance criteria for email validation
```C
#this.get("mapped.subject") && #this.get("mapped.subject").toString().matches("^[a-zA-Z0-9_.±]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$")? @java.lang.Boolean@TRUE:@java.lang.Boolean@FALSE
```

### 8. Issuance criteria for restricting access via country/ region
```C
#this.get("mapped.country")!=null && #this.get("mapped.country").toString().matches("(?i).*Pakistan.*|.*China.*|.*Russia.*|.*Iran.*")?@java.lang.Boolean@FALSE:@java.lang.Boolean@TRUE
```