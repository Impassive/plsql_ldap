create or replace package wim_slapd AS
/*********************************************************************************************************
* Authenticate user
*********************************************************************************************************/

    function authenticate(
        login_name VARCHAR2,
        passwd VARCHAR2)
    return PLS_INTEGER;

/*********************************************************************************************************
* Create user | requires Slapd Administrator user
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
* Reset password | requires Slapd Administrator user
*********************************************************************************************************/

    function password_reset(
        login_name VARCHAR2,
        new_passwd VARCHAR2)
    return PLS_INTEGER;

--
/*********************************************************************************************************
* lock & unlock account | requires Slapd Administrator user
* currently modify only userpassword attribute, if necessary, add sambda NTLM attributes to lock samba account too
* Possible values:
* 0 - lock
* 1 - unlock
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
* Assign user to the group
*********************************************************************************************************/   

    function assign_group(
        login_name VARCHAR2,
        group_name VARCHAR2) 
    return PLS_INTEGER; 

/*********************************************************************************************************
* Deassign user from the group
*********************************************************************************************************/   

    function deassign_group(
        login_name VARCHAR2,
        group_name VARCHAR2) 
    return PLS_INTEGER; 

/*********************************************************************************************************
* Search attributes by login_name
*********************************************************************************************************/   

    function get_attributes(
        login_name VARCHAR2) 
    return VARCHAR2;

/*********************************************************************************************************
* Search for groups and members
*********************************************************************************************************/ 

    function get_groups
    return VARCHAR2;

end wim_slapd;
/
show_error

