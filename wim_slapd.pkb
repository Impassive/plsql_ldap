create or replace package BODY wim_slapd AS    
    g_ldap_session  DBMS_LDAP.session;
    g_retval   PLS_INTEGER;
    g_ldap_host  VARCHAR2(256);
    g_ldap_port  VARCHAR2(256);
    g_ldap_base  VARCHAR2(256);
    g_wdt_ldap_base VARCHAR2(256);
    g_wdt_group_base VARCHAR2(256);
    g_admin_user VARCHAR2(256);
    g_admin_passwd VARCHAR2(256);
    g_wallet_path VARCHAR2(256);
    g_wallet_passwd VARCHAR2(256);
    g_scope_prefix VARCHAR2(32);
    
    function get_user_dn(g_ldap_session DBMS_LDAP.session, login_name VARCHAR2) return VARCHAR2 IS
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_message DBMS_LDAP.MESSAGE;
        l_mes DBMS_LDAP.MESSAGE;
        BEGIN
            --get user DN
            l_entry_str_col(1) := 'uid';
            g_retval := DBMS_LDAP.search_s(g_ldap_session, g_wdt_ldap_base, 
                              DBMS_LDAP.SCOPE_ONELEVEL,
                              'uid='||login_name,
                              l_entry_str_col,
                              0,
                              l_entry_message);
                
            l_mes := DBMS_LDAP.first_entry(g_ldap_session, l_entry_message);
            
            return dbms_ldap.get_dn(g_ldap_session, l_mes);
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_extra => logger.sprintf('User DN for uid[%s] not found', login_name),
                    p_scope => g_scope_prefix || 'get_user_dn');
                raise;
            
    END get_user_dn;
    
    function authenticate(login_name VARCHAR2, passwd VARCHAR2) return PLS_INTEGER IS       
        BEGIN      
        g_retval := -1;
        DBMS_LDAP.use_exception := true;
                
        -- Initialize ldap library and get session handle.
        g_ldap_session := dbms_ldap.init(g_ldap_host, g_ldap_port);
                
        --Bind as admin to find user dn
        g_retval := dbms_ldap.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
        
        --Bind as user
        g_retval := dbms_ldap.simple_bind_s(g_ldap_session,get_user_dn(g_ldap_session, login_name), passwd);
                
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
            
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session,g_admin_user, g_admin_passwd);
            
            --list of attributes to get
            l_entry_str_col(1) := 'uidnumber'; --unique userID
            l_entry_str_col(2) := 'uid'; --login_name
            l_entry_str_col(3) := 'sn'; --last name
            l_entry_str_col(4) := 'givenname'; --first name
            l_entry_str_col(5) := 'cn'; --full name
            l_entry_str_col(6) := 'userPassword'; --to check if locked
            l_entry_str_col(6) := 'memberOf';
            
            g_retval := DBMS_LDAP.search_s(g_ldap_session, g_wdt_ldap_base, 
                              DBMS_LDAP.SCOPE_ONELEVEL,
                              'uid='||login_name,
                              l_entry_str_col,
                              0,
                              l_entry_message);
            
            l_entry_str_col.DELETE;
            
            l_mes := DBMS_LDAP.first_entry(g_ldap_session, l_entry_message);
            
            APEX_JSON.initialize_clob_output;
            APEX_JSON.open_object;
            APEX_JSON.open_object(login_name);  
            
            IF l_mes IS NOT NULL THEN
                APEX_JSON.write('dn', dbms_ldap.get_dn(g_ldap_session, l_mes));
                l_entry_attribute := dbms_ldap.first_attribute(g_ldap_session, l_mes, l_berval_element);
                WHILE l_entry_attribute IS NOT NULL LOOP
                    l_entry_str_col := dbms_ldap.get_values(g_ldap_session, l_mes, l_entry_attribute);
                    i := l_entry_str_col.first;
                    WHILE i IS NOT NULL LOOP
                        IF l_entry_attribute = 'userPassword' THEN
                            APEX_JSON.write(l_entry_attribute, CASE WHEN instr(l_entry_str_col(i),'!') != 0 THEN '0' ELSE '1' END);
                        ELSE
                            APEX_JSON.write(l_entry_attribute, l_entry_str_col(i));
                        END IF;
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
    
    function add_user(login_name VARCHAR2, first_name VARCHAR2, last_name VARCHAR2, passwd VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 23;
        l_uidnumber VARCHAR2(20);
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_passwd_hash RAW(2000);
        BEGIN
            
            --use table with autonoumous transaction or use sequence
            l_uidnumber := wim_slapd_uidnum_seq.nextval;    
            
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
    
            -- Initialize ldap library and get session handle.
            g_ldap_session := dbms_ldap.init(g_ldap_host, g_ldap_port);
                
            -- Bind
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := dbms_ldap.create_mod_array(l_ldap_attr_num);
                
            -- cn = First_Name Last_Name, dc=wdt, dc=com:
            l_entry_str_col(1) := initcap(first_name) || ' ' || initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD, 'cn',l_entry_str_col);
                
            --objectClasses
            l_entry_str_col(1) := 'posixAccount';
            l_entry_str_col(2) := 'inetOrgPerson';
            l_entry_str_col(3) := 'organizationalPerson';
            l_entry_str_col(4) := 'person';
            l_entry_str_col(5) := 'top';
            l_entry_str_col(6) := 'sambaSamAccount';
            l_entry_str_col(7) := 'shadowAccount';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'objectclass',l_entry_str_col);
            
            --release collection
            l_entry_str_col.DELETE;
            
            --gidnumber
            l_entry_str_col(1) := '10000';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'gidnumber',l_entry_str_col);
                
            --givenname
            l_entry_str_col(1) := initcap(first_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'givenname',l_entry_str_col);
                
            --homedirectory
            l_entry_str_col(1) := '/home/'|| login_name;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'homedirectory',l_entry_str_col);
                
            --loginshell
            l_entry_str_col(1) := '/bin/bash';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'loginshell',l_entry_str_col);
                
            --user password
            l_passwd_hash := dbms_crypto.hash( utl_i18n.string_to_raw(passwd, 'AL32UTF8'), dbms_crypto.hash_sh1);
            l_entry_str_col(1) := '{SHA}' || utl_raw.cast_to_varchar2(utl_encode.base64_encode(l_passwd_hash));
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'userpassword',l_entry_str_col);
                
            --sn
            l_entry_str_col(1) := initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sn',l_entry_str_col);

            --uid
            l_entry_str_col(1) := lower(login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'uid',l_entry_str_col);
                
            --uidnumber (CRITICAL)
            l_entry_str_col(1) := l_uidnumber;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'uidNumber', l_entry_str_col);
            
            --sambdasid (for sbp-nas auth)
            l_entry_str_col(1) := 'S-1-5-21-4139673485-2939801457-1072223612-500';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambasid', l_entry_str_col);
            
            --sambda primary group sid 
            l_entry_str_col(1) := 'S-1-5-21-4139673485-2939801457-1072223612-513';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambaprimarygroupsid', l_entry_str_col);
            
            --sambaacctflags
            l_entry_str_col(1) := '[XU         ]';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambaacctflags', l_entry_str_col);
            
            --sambdadomainname
            l_entry_str_col(1) := 'wdtsamba';
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambadomainname', l_entry_str_col);
            
            --sambdaLMpassword
            --TODO: INCORRECT HASH VALUE
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambalmpassword', l_entry_str_col);
            
            --sambdaNTpassword
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'sambantpassword', l_entry_str_col);
                        
            --push
            g_retval := DBMS_LDAP.add_s(g_ldap_session, 'cn='|| initcap(first_name) || ' ' || initcap(last_name) ||','|| g_wdt_ldap_base, l_entry_arr);
            
            --update wim_slapd_users table
            insert into wim_slapd_users(uidnumber, login_name, full_name)
                values(to_number(l_uidnumber), login_name, initcap(first_name) || ' ' || initcap(last_name));
                           
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
    
    function assign_group(login_name VARCHAR2, group_name VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 1;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_group_dn VARCHAR2(256) := 'cn='|| group_name ||','|| g_wdt_group_base ;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;

            -- Initialize ldap library and get session handle.
            g_ldap_session := dbms_ldap.init(g_ldap_host, g_ldap_port);
                
            -- Bind
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
            
            --allocate memory for new group member
            l_entry_arr := dbms_ldap.create_mod_array(l_ldap_attr_num);
            
            --fill new group member        
            l_entry_str_col(1) := get_user_dn(g_ldap_session, login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_ADD,'member',l_entry_str_col);
            
            --push
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, l_group_dn , l_entry_arr);
              
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
                       
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'assign_group');
                raise;
                    
    end assign_group;
    
    function deassign_group(login_name VARCHAR2, group_name VARCHAR2) return PLS_INTEGER IS
        l_ldap_attr_num NUMBER(2) := 1;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_group_dn VARCHAR2(256) := 'cn='|| group_name ||','|| g_wdt_group_base ;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;

            -- Initialize ldap library and get session handle.
            g_ldap_session := dbms_ldap.init(g_ldap_host, g_ldap_port);
                
            -- Bind
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
            
            --allocate memory for new group member
            l_entry_arr := dbms_ldap.create_mod_array(l_ldap_attr_num);
            
            --fill new group member        
            l_entry_str_col(1) := get_user_dn(g_ldap_session, login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_DELETE,'member',l_entry_str_col);
            
            --push
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, l_group_dn , l_entry_arr);
              
            --release memory
            DBMS_LDAP.free_mod_array(l_entry_arr);
            
            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
                       
            return g_retval;
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'deassign_group');
                raise;
                    
    end deassign_group;
        
    function self_password_change(login_name VARCHAR2, old_passwd VARCHAR2, new_passwd VARCHAR2) return PLS_INTEGER AS
        l_ldap_attr_num NUMBER(2) := 4;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_passwd_hash RAW(2000);
        l_user_dn VARCHAR2(1000);
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
            
            -- Bind as admin to find user dn
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session,g_admin_user, g_admin_passwd);
            
            l_user_dn:= get_user_dn(g_ldap_session, login_name);
            
            -- Bind as user
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session, l_user_dn, old_passwd);
            
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
            
            --user password
            l_passwd_hash := dbms_crypto.hash( utl_i18n.string_to_raw(new_passwd, 'AL32UTF8'), dbms_crypto.hash_sh1);
            l_entry_str_col(1) := '{SHA}' || utl_raw.cast_to_varchar2(utl_encode.base64_encode(l_passwd_hash));
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'userpassword',l_entry_str_col);
            
            --sambdaLMpassword
            --TODO: INCORRECT HASH VALUE
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (new_passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambalmpassword', l_entry_str_col);
            
            --sambdaNTpassword
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (new_passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambantpassword', l_entry_str_col);
            
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, l_user_dn ,l_entry_arr);
                            
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
    
    function password_reset(login_name VARCHAR2, new_passwd VARCHAR2) return PLS_INTEGER AS
        l_ldap_attr_num NUMBER(2) := 4;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_passwd_hash RAW(2000);
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
            
            -- Bind
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session,g_admin_user, g_admin_passwd);
            
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
            
            --user password
            l_passwd_hash := dbms_crypto.hash( utl_i18n.string_to_raw(new_passwd, 'AL32UTF8'), dbms_crypto.hash_sh1);
            l_entry_str_col(1) := '{SHA}' || utl_raw.cast_to_varchar2(utl_encode.base64_encode(l_passwd_hash));
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'userpassword',l_entry_str_col);
            
            --sambdaLMpassword
            --TODO: INCORRECT HASH VALUE
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (new_passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambalmpassword', l_entry_str_col);
            
            --sambdaNTpassword
            l_entry_str_col(1) := DBMS_CRYPTO.hash (UTL_I18N.STRING_TO_RAW (new_passwd, 'AL16UTF16LE'), DBMS_CRYPTO.HASH_MD4);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambantpassword', l_entry_str_col);
            
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
    
    --locks samba and userpassword attributes
    function account_control(login_name VARCHAR2, userAccountControl VARCHAR2) return PLS_INTEGER AS
        l_ldap_attr_num NUMBER(2) := 3;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_modified DBMS_LDAP.STRING_COLLECTION;
        l_sambaacctflags DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        l_entry_message DBMS_LDAP.MESSAGE;
        l_mes DBMS_LDAP.MESSAGE;
        l_entry_attribute VARCHAR2(256);
        i PLS_INTEGER;
        l_berval_element DBMS_LDAP.BER_ELEMENT;
        l_user_dn VARCHAR2(1000);
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get sessWion handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
            
            -- Bind
            g_retval := dbms_ldap.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
            
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
            
            --get user dn
            l_user_dn := get_user_dn(g_ldap_session, login_name);
            
            --get user password
            l_entry_str_col(1) := 'userpassword';
            g_retval := DBMS_LDAP.search_s(g_ldap_session, l_user_dn, 
                              DBMS_LDAP.SCOPE_BASE,
                              'objectclass=*',
                              l_entry_str_col,
                              0,
                              l_entry_message); 
                              
            l_mes := DBMS_LDAP.first_entry(g_ldap_session, l_entry_message);
            
            l_entry_attribute := DBMS_LDAP.first_attribute(g_ldap_session, l_mes, l_berval_element);
            
            IF l_entry_attribute IS NOT NULL THEN
                l_entry_str_col := DBMS_LDAP.get_values(g_ldap_session, l_mes, l_entry_attribute);
                i := l_entry_str_col.first;
                dbms_output.put_line(LPAD(l_entry_attribute, 15) || ' = ' || l_entry_str_col(i)); 

                CASE WHEN userAccountControl = '0' and instr(l_entry_str_col(i), '}!') = 0 THEN 
                            l_entry_str_col(i) := replace(l_entry_str_col(i), '}', '}!'); dbms_output.put_line('LOCKED '|| l_entry_str_col(i));
                            l_sambaacctflags(1) := '[XUD        ]';
                            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambaacctflags',l_sambaacctflags);
                    WHEN userAccountControl = '1' and instr(l_entry_str_col(i), '}!') != 0 THEN 
                            l_entry_str_col(i) := replace(l_entry_str_col(i), '!'); dbms_output.put_line('UNLOCKED '|| l_entry_str_col(i));
                            l_sambaacctflags(1) := '[XU         ]';
                            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sambaacctflags',l_sambaacctflags);
                    ELSE dbms_output.put_line('lock-unlock confuse. nothing was changed');
                    END CASE;
                --modify attributes              
                l_entry_modified(1) := l_entry_str_col(i);
                DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'userpassword',l_entry_modified);
            END IF;
                         
            --push
            g_retval := DBMS_LDAP.modify_s(g_ldap_session, l_user_dn ,l_entry_arr);

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

    function attribute_change(old_login_name VARCHAR2, login_name VARCHAR2, first_name VARCHAR2, last_name VARCHAR2) return PLS_INTEGER AS
        l_ldap_attr_num NUMBER(2) := 10;
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_arr DBMS_LDAP.MOD_ARRAY;
        BEGIN
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
            
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
                               
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session, g_admin_user, g_admin_passwd);
                
            --allocate memory for the specified amount of ldap attributes 
            l_entry_arr := DBMS_LDAP.create_mod_array(l_ldap_attr_num);
            
            --uid
            l_entry_str_col(1) := lower(login_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE, 'uid', l_entry_str_col);
                          
            --sn
            l_entry_str_col(1) := initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'sn',l_entry_str_col);
                
            --givenname
            l_entry_str_col(1) := initcap(first_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'givenname',l_entry_str_col);
                
            --displayName
            l_entry_str_col(1) := initcap(first_name) || ' ' || initcap(last_name);
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'displayname',l_entry_str_col);
                
            --homedirectory
            l_entry_str_col(1) := '/home/'|| login_name;
            DBMS_LDAP.populate_mod_array(l_entry_arr,DBMS_LDAP.MOD_REPLACE,'homedirectory',l_entry_str_col);
                                           
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
    
    function get_groups return VARCHAR2 IS       
        l_entry_str_col DBMS_LDAP.STRING_COLLECTION;
        l_entry_message DBMS_LDAP.MESSAGE;
        l_mes DBMS_LDAP.MESSAGE;
        l_json VARCHAR2(4096);
        l_entry_attribute VARCHAR2(256);
        i PLS_INTEGER;
        n PLS_INTEGER := 1;
        l_berval_element DBMS_LDAP.BER_ELEMENT;
        BEGIN      
            g_retval := -1;
            DBMS_LDAP.use_exception := true;
                
            -- Initialize ldap library and get session handle.
            g_ldap_session := DBMS_LDAP.init(g_ldap_host, g_ldap_port);
            
            -- Bind
            g_retval := DBMS_LDAP.simple_bind_s(g_ldap_session,g_admin_user, g_admin_passwd);
            
            --list of attributes to get
            l_entry_str_col(1) := 'cn'; --group cn
            l_entry_str_col(2) := 'member'; --group member DN
            
            g_retval := DBMS_LDAP.search_s(g_ldap_session, g_ldap_base, 
                              DBMS_LDAP.SCOPE_SUBTREE,
                              'objectClass=groupOfNames',
                              l_entry_str_col,
                              0,
                              l_entry_message);
            
            l_entry_str_col.DELETE;
            
            l_mes := DBMS_LDAP.first_entry(g_ldap_session, l_entry_message);
            
            APEX_JSON.initialize_clob_output;
            APEX_JSON.open_object;  
            
            WHILE l_mes IS NOT NULL and n<= dbms_ldap.count_entries(g_ldap_session, l_entry_message) LOOP
                APEX_JSON.open_object(dbms_ldap.get_dn(g_ldap_session, l_mes));  
                l_entry_attribute := dbms_ldap.first_attribute(g_ldap_session, l_mes, l_berval_element);
                WHILE l_entry_attribute IS NOT NULL LOOP
                    l_entry_str_col := dbms_ldap.get_values(g_ldap_session, l_mes, l_entry_attribute);
                    i := l_entry_str_col.first;
                    WHILE i IS NOT NULL LOOP
                        IF l_entry_attribute = 'member' THEN
                            APEX_JSON.write(l_entry_attribute || '#' || i, l_entry_str_col(i));
                        ELSE
                            APEX_JSON.write(l_entry_attribute, l_entry_str_col(i));
                        END IF;
                        i := l_entry_str_col.next(i);
                    END LOOP;
                    l_entry_attribute := dbms_ldap.next_attribute(g_ldap_session, l_mes, l_berval_element);
                END LOOP;
                n:= n+1;
                l_mes := DBMS_LDAP.next_entry(g_ldap_session, l_entry_message);
                APEX_JSON.close_object;
            END LOOP;
            
            APEX_JSON.close_object;
            l_json := APEX_JSON.get_clob_output;

            --unbind
            g_retval := DBMS_LDAP.unbind_s(ld => g_ldap_session);
                    
            return l_json; 
            
            EXCEPTION
            WHEN OTHERS THEN
                logger.log_error(
                    p_scope => g_scope_prefix || 'get_groups');
                raise;
                
        end get_groups;
    
    BEGIN
        select value into g_ldap_host 
            from devldap.wdt_app_settings 
                where section = 'SLAPD' and name = 'LDAP_HOST';
        select value into g_ldap_port 
            from devldap.wdt_app_settings 
                where section = 'SLAPD' and name = 'LDAP_PORT';
        select value into g_ldap_base 
            from devldap.wdt_app_settings 
                where section = 'SLAPD' and name = 'LDAP_BASE';
        select value into g_admin_user 
            from devldap.wdt_app_settings 
                where section = 'SLAPD' and name = 'LDAP_ADMIN_USER';
        select value into g_admin_passwd 
            from devldap.wdt_app_settings 
                where section = 'SLAPD' and name = 'LDAP_ADMIN_PASSWD';
        select value into g_wallet_path 
            from devldap.wdt_app_settings 
                where section = 'WALLET' and name = 'WALLET_PATH';
        select value into g_wallet_passwd 
            from devldap.wdt_app_settings 
                where section = 'WALLET' and name = 'WALLET_PASSWD';
                
        g_wdt_ldap_base  := 'ou=Employees,' || g_ldap_base;
        g_wdt_group_base := 'ou=Groups,' || g_ldap_base; 
        g_admin_user := 'uid=' || g_admin_user ||',' || g_ldap_base; 
        g_scope_prefix := lower($$PLSQL_UNIT) || '.';
        
        EXCEPTION
        WHEN OTHERS THEN
            logger.log_error(
                p_scope => g_scope_prefix || 'package_initialization');
            raise;
            
end wim_slapd;
/
show_error

/
show error
