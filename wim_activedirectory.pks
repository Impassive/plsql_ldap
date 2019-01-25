create or replace package wim_activedirectory AS
/*********************************************************************************************************
* Authenticate user
*********************************************************************************************************/

    function authenticate(
        login_name VARCHAR2,
        passwd VARCHAR2)
    return PLS_INTEGER;

/*********************************************************************************************************
* Create user | requires AD Administrator user
*********************************************************************************************************/

    function add_user(
        login_name VARCHAR2,
        first_name VARCHAR2,
        last_name VARCHAR2,
        passwd VARCHAR2)
    return PLS_INTEGER;

/*********************************************************************************************************
* Change password | user self change
*********************************************************************************************************/

    function self_password_change(
        login_name VARCHAR2,
        old_passwd VARCHAR2,
        new_passwd VARCHAR2)
    return PLS_INTEGER;

--
/*********************************************************************************************************
* Reset password | requires AD Administrator user
*********************************************************************************************************/
    function password_reset(
        login_name VARCHAR2,
        new_passwd VARCHAR2)
    return PLS_INTEGER;

--
/*********************************************************************************************************
* lock & unlock account | requires AD Administrator user
* Possible values see here https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
*   some default values:
*   512 - Enabled account with standard password policy
*   514 - Disabled account with standard password policy
*   66048 - Enabled, password never expires
*********************************************************************************************************/

    function account_control(
        login_name VARCHAR2,
        userAccountControl VARCHAR2) 
    return PLS_INTEGER;
    
/*********************************************************************************************************
* Change attributes | requires AD Administrator user
* Doesn't change DN!
*********************************************************************************************************/ 

    function attribute_change(
        old_login_name VARCHAR2,
        login_name VARCHAR2,
        first_name VARCHAR2,
        last_name VARCHAR2) 
    return PLS_INTEGER;

/*********************************************************************************************************
* Search attributes by login_name
*********************************************************************************************************/   

    function get_attributes(
        login_name VARCHAR2) 
    return VARCHAR2;
    
end wim_activedirectory;

/
show error