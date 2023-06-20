userAgent, err := tpgresource.GenerateUserAgentString(d, config.UserAgent)
if err != nil {
return err
}
email, ok := d.GetOk("email")
if !ok {
return fmt.Errorf("error registering ACME account, email address is required")
}
privateKeyPem, _ := d.GetOk("private_key_pem")
accountUri, ok := d.GetOk("account_uri")
if !ok {
return fmt.Errorf("error updating account, account URI is required.")
}
eabKeyId, ok := d.GetOk("eab_key_id")
if !ok {
return fmt.Errorf("error registering ACME account, registration server is required")
}
eabHmacKeyUrlEncoded, ok := d.GetOk("eab_hmac_key")
if !ok {
return fmt.Errorf("error registering ACME account, registration server is required")
}
if d.HasChange("email") {
log.Printf("[DEBUG] Updating ACME account email: %s userAgent: %s", email, userAgent)
err = updateAccountEmail(accountUri.(string), privateKeyPem.(string), email.(string), eabKeyId.(string), eabHmacKeyUrlEncoded.(string))
return nil
}
if d.HasChange("private_key_pem") {
log.Printf("[DEBUG] Private Key changed, updating ACME account")
oldValue, newValue := d.GetChange("private_key_pem")
accountUri, ok := d.GetOk("account_uri")
if !ok {
return fmt.Errorf("error deactivating account, account URI is required.")
}
basePath, err := tpgresource.ReplaceVars(d, config, "{{PublicCABasePath}}")
if err != nil {
return err
}
isStagingEnv := strings.Contains(basePath, "preprod-")
err = accountKeyRollover(accountUri.(string), isStagingEnv, oldValue.(string), newValue.(string))
if err != nil {
return fmt.Errorf("error occurred changing the private key: %s", err)
}
}
if err != nil {
return fmt.Errorf("error occurred updating the account: %s", err)
}
return nil