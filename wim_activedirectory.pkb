create or replace package BODY wim_activedirectory AS
    g_ldap_session  DBMS_LDAP.session;
    g_retval   PLS_INTEGER; 
    g_ldap_host  VARCHAR2(256);
    g_ldap_port  VARCHAR2(32);
    g_ldap_base  VARCHAR2(256);
    g_wdt_ldap_base VARCHAR2(256);
    g_admin_user VARCHAR2(256);
    g_admin_passwd VARCHAR2(256);
    g_wallet_path VARCHAR2(256);
    g_wallet_passwd VARCHAR2(256);
    g_userPincipalname_suffix VARCHAR2(256);
    g_scope_prefix VARCHAR2(32);

    function get_user_dn(ldap_session DBMS_LDAP.session, login_name VARCHAR2) return VARCHAR2 IS
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_message DBMS_LDAP.MESSAGE;
        l_mes DBMS_LDAP.MESSAGE;
        BEGIN
            --get user DN
            l_entry_str_col(1) := 'userPrincipalname';
            g_retval := DBMS_LDAP.search_s(ldap_session, g_wdt_ldap_base, 
                              DBMS_LDAP.SCOPE_ONELEVEL,
                              'userPrincipalname='||login_name||g_userPincipalname_suffix,
                              l_entry_str_col,
                              0,
                              l_entry_message);
                
            l_mes := DBMS_LDAP.first_entry(ldap_session, l_entry_message);
            
            return dbms_ldap.get_dn(ldap_session, l_mes);
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_extra => logger.sprintf('User DN for userPrincipalname[%s] not found', login_name),
                    p_scope => g_scope_prefix || 'get_user_dn');
                raise;          
            
    END get_user_dn;
    
    function authenticate(login_name VARCHAR2, passwd VARCHAR2) return PLS_INTEGER IS       
        BEGIN      
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
                
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            -- Open Wallet for SSL.
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2);
            
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session,login_name||g_userPincipalname_suffix, passwd);
                
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
                    
            return g_retval; 
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'authenticate');
                raise;
                
        end authenticate;
        
    function get_attributes(login_name VARCHAR2) return VARCHAR2 IS       
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_message DBMS_LDAP.MESSAGE;
        l_mes DBMS_LDAP.MESSAGE;
        l_json VARCHAR2(4096);
        l_entry_attribute VARCHAR2(256);
        i PLS_INTEGER;
        l_berval_element DBMS_LDAP.BER_ELEMENT;
        BEGIN      
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
                
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            -- Open Wallet for SSL.
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2);
            
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session,g_admin_user, g_admin_passwd);
            
            --list of attributes to get
            l_entry_str_col(1) := 'userPrincipalname'; --login@domain
            l_entry_str_col(2) := 'sn'; --last name
            l_entry_str_col(3) := 'givenname'; --first name
            l_entry_str_col(4) := 'cn'; --full name
            l_entry_str_col(5) := 'userAccountControl';
            l_entry_str_col(6) := 'sAMAccountName';--login_name
            
            g_retval := DBMS_LDAP.search_s(g_ldap_session, g_wdt_ldap_base, 
                              DBMS_LDAP.SCOPE_ONELEVEL,
                              'userPrincipalname='||login_name||g_userPincipalname_suffix,
                              l_entry_str_col,
                              0,
                              l_entry_message);
            
            l_entry_str_col.DELETE;
            
            APEX_JSON.initialize_clob_output;
            APEX_JSON.open_object;
            APEX_JSON.open_object(login_name);           

            l_mes := DBMS_LDAP.first_entry(g_ldap_session, l_entry_message);
            
            IF l_mes IS NOT NULL THEN
                APEX_JSON.write('dn', dbms_ldap.get_dn(g_ldap_session, l_mes));
                l_entry_attribute := dbms_ldap.first_attribute(g_ldap_session, l_mes, l_berval_element);
                WHILE l_entry_attribute IS NOT NULL LOOP
                    l_entry_str_col := dbms_ldap.get_values(g_ldap_session, l_mes, l_entry_attribute);
                    i := l_entry_str_col.first;
                    WHILE i IS NOT NULL LOOP
                        APEX_JSON.write(l_entry_attribute, l_entry_str_col(i));
                        i := l_entry_str_col.next(i);                       
                    END LOOP;
                    l_entry_attribute := dbms_ldap.next_attribute(g_ldap_session, l_mes, l_berval_element);
                END LOOP;
            END IF;          
            
            APEX_JSON.close_object;
            APEX_JSON.close_object;
            l_json := APEX_JSON.get_clob_output;
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
                    
            return l_json; 
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'get_attributes');
                raise;
                
        end get_attributes;
        
    --requires AD Administrator user
    function add_user(login_name VARCHAR2, first_name VARCHAR2, last_name VARCHAR2, passwd VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 12;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_ber_col DBMS_LDAP.BERVAL_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            DBMS_LDAP.use_exception := true;
            g_retval := -1;
     
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            -- Open Wallet for SSL.
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2); 
                
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
                   
            --sAMAccountName
            l_entry_str_col(1) := lower(login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD, 'sAMAccountName',l_entry_str_col);
                
            -- cn = First_Name Last_Name, dc=wdt, dc=com...:
            l_entry_str_col(1) := initcap(first_name) || ' ' || initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD, 'cn',l_entry_str_col);
                
            --sn
            l_entry_str_col(1) := initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sn',l_entry_str_col);
                
            --givenname
            l_entry_str_col(1) := initcap(first_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'givenname',l_entry_str_col);
                
            --displayName
            l_entry_str_col(1) := initcap(first_name) || ' ' || initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'displayname',l_entry_str_col);
                
            --userPrincipalname
            l_entry_str_col(1) := lower(login_name) || g_userPincipalname_suffix;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'userPrincipalname',l_entry_str_col);
                              
            --objectClasses
            l_entry_str_col(1) := 'top';
            l_entry_str_col(2) := 'person';
            l_entry_str_col(3) := 'organizationalPerson';
            l_entry_str_col(4) := 'user';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'objectclass',l_entry_str_col);
                
            --user password
            l_entry_ber_col(1):= UTL_RAW.cast_to_raw(convert('"'||passwd||'"', 'AL16UTF16LE'));
            DBMS_LDAP.populate_mod_array(l_entry_arr, DBMS_LDAP.MOD_ADD,'unicodePwd', l_entry_ber_col);
                           
            --push                   
            g_retval := DBMS_LDAP.add_s(g_ldap_session, 'cn='||initcap(first_name) || ' ' || initcap(last_name)|| ','|| g_wdt_ldap_base ,l_entry_arr);
            
            --update wim_slapd_users table
            insert into wim_activedirectory_users(uidnumber, login_name, full_name)
                values(wim_activedirectory_uidnum_seq.nextval ,lower(login_name) || g_userPincipalname_suffix, initcap(first_name) || ' ' || initcap(last_name));
                                                         
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
            
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'add_user');
                raise;
            
    end add_user;
    
    function self_password_change(login_name VARCHAR2, old_passwd VARCHAR2, new_passwd VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 2;
        l_entry_str_col DBMS_LDAP.BERVAL_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            -- Open Wallet for SSL.
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2); 
                
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session,login_name||g_userPincipalname_suffix, old_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
                   
            --swap passwords
            l_entry_str_col(1):= UTL_RAW.cast_to_raw(convert('"'||old_passwd||'"', 'AL16UTF16LE'));
            DBMS_LDAP.populate_mod_array(l_entry_arr, DBMS_LDAP.MOD_DELETE,'unicodePwd', l_entry_str_col);
                
            l_entry_str_col(1):= UTL_RAW.cast_to_raw(convert('"'||new_passwd||'"', 'AL16UTF16LE'));
            DBMS_LDAP.populate_mod_array(l_entry_arr, DBMS_LDAP.MOD_ADD,'unicodePwd', l_entry_str_col);
            
            --push              
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, get_user_dn(g_ldap_session, login_name) ,l_entry_arr);
                            
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
     
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'self_password_change');
                raise;
            
        end self_password_change;
        
    function password_reset(login_name VARCHAR2, new_passwd VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 1;
        l_entry_str_col DBMS_LDAP.BERVAL_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            -- Open Wallet for SSL.
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2); 
                
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
                   
            --unicodePwd
            l_entry_str_col(1):= UTL_RAW.cast_to_raw(convert('"'||new_passwd||'"', 'AL16UTF16LE'));
            DBMS_LDAP.populate_mod_array(l_entry_arr, DBMS_LDAP.MOD_REPLACE,'unicodePwd', l_entry_str_col);
            
            --push                          
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, get_user_dn(g_ldap_session, login_name) ,l_entry_arr);
                          
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
     
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'password_reset');
                raise;
                
    end password_reset;
        
    function account_control(login_name VARCHAR2, userAccountControl VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 2;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            --Open SSL connection
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2); 
                
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
                
            --Account Control
            l_entry_str_col(1) := userAccountControl;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'userAccountControl',l_entry_str_col);    
                
            --push               
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, get_user_dn(g_ldap_session, login_name), l_entry_arr);
                
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
                
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
     
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'account_control');
                raise;
                
    end account_control; 

    function attribute_change(old_login_name VARCHAR2, login_name VARCHAR2, first_name VARCHAR2, last_name VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 10;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                
            --Open SSL connection
            g_retval := DBMS_LDAP.open_ssl(g_ldap_session, g_wallet_path, g_wallet_passwd, 2); 
                
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
            
            --sAMAccountName
            l_entry_str_col(1) := lower(login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE, 'sAMAccountName',l_entry_str_col);
                          
            --sn
            l_entry_str_col(1) := initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sn',l_entry_str_col);
                
            --givenname
            l_entry_str_col(1) := initcap(first_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'givenname',l_entry_str_col);
                
            --displayName
            l_entry_str_col(1) := initcap(first_name) || ' ' || initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'displayname',l_entry_str_col);
            
            --userPrincipalname
            l_entry_str_col(1) := lower(first_name || '.' || last_name) || g_userPincipalname_suffix;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'userPrincipalname',l_entry_str_col);
                
            --push              
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, get_user_dn(g_ldap_session, old_login_name) ,l_entry_arr);
                            
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
            
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'attribute_change');
                raise;
                
    end attribute_change;
    
    BEGIN
        
        select value into g_ldap_host 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_HOST';
        select value into g_ldap_port 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_PORT';
        select value into g_ldap_base 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_BASE';        
        select value into g_admin_user 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_ADMIN_USER';
        select value into g_admin_passwd 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_ADMIN_PASSWD';
        select value into g_userPincipalname_suffix 
            from devldap.wdt_app_settings 
                where section = 'ACTIVE_DIRECTORY' and name = 'LDAP_DOMAIN';
        select value into g_wallet_path 
            from devldap.wdt_app_settings 
                where section = 'WALLET' and name = 'WALLET_PATH';
        select value into g_wallet_passwd 
            from devldap.wdt_app_settings 
                where section = 'WALLET' and name = 'WALLET_PASSWD';
        
        g_wdt_ldap_base := 'ou=Users,ou=WDT,'||g_ldap_base;
        g_userPincipalname_suffix := '@'||g_userPincipalname_suffix;
        g_admin_user := g_admin_user||g_userPincipalname_suffix;
        g_scope_prefix := lower($$PLSQL_UNIT) || '.';
        
        EXCEPTION
        WHEN OTHERS THEN
            logger.log_error(
                p_scope => g_scope_prefix || 'package_initialization');
            raise;
    
end wim_activedirectory;

/
show error