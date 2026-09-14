{
  "subject": {
    "organization": {{ toJson .Insecure.User.tenantId }},
    "commonName": {{ toJson .Insecure.User.subjectId }}
  },
  "uris": [{{ toJson .Insecure.User.identityUri }}],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "basicConstraints": {
    "isCA": false
  }
}
