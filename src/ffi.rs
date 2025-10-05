use crate::config::Config;
use crate::validator::safe_validate;
use pgrx::pg_sys::pstrdup;
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::ptr;

#[repr(C)]
pub struct ValidatorModuleState {
    pub sversion: ::std::os::raw::c_int,
    pub private_data: *mut ::std::os::raw::c_void,
    pub options: *const *const std::os::raw::c_char,
}

#[repr(C)]
pub struct ValidatorModuleResult {
    authorized: bool,
    authn_id: *mut ::std::os::raw::c_char,
}

pub type ValidatorStartupCallback = unsafe extern "C" fn(*mut ValidatorModuleState);
pub type ValidatorShutdownCallback = unsafe extern "C" fn(*mut ValidatorModuleState);
pub type ValidatorValidateCallback = unsafe extern "C" fn(
    *const ValidatorModuleState,
    *const ::std::os::raw::c_char,
    *const ::std::os::raw::c_char,
    *mut ValidatorModuleResult,
) -> bool;

// Struct exported to PostgreSQL
#[repr(C)]
pub struct OAuthValidatorCallbacks {
    pub magic: u64,
    pub startup_cb: Option<ValidatorStartupCallback>,
    pub shutdown_cb: Option<ValidatorShutdownCallback>,
    pub validate_cb: Option<ValidatorValidateCallback>,
}

// Magic constant (matches PG_OAUTH_VALIDATOR_MAGIC in C)
pub const PG_OAUTH_VALIDATOR_MAGIC: u64 = 0x1234_5678_9ABC_DEF0;

unsafe fn get_hba_options(state: *const ValidatorModuleState) -> HashMap<String, String> {
    let mut map = HashMap::new();

    if state.is_null() || (*state).options.is_null() {
        return map; // no options
    }

    let mut i = 0;
    loop {
        let opt_ptr = *(*state).options.add(i);
        if opt_ptr.is_null() {
            break; // null-terminated
        }

        let opt_cstr = CStr::from_ptr(opt_ptr);
        if let Ok(opt_str) = opt_cstr.to_str() {
            // split "key=value" into (key, value)
            if let Some(eq_pos) = opt_str.find('=') {
                let key = &opt_str[..eq_pos];
                let value = &opt_str[eq_pos + 1..];
                map.insert(key.to_string(), value.to_string());
            }
        }

        i += 1;
    }

    map
}

extern "C" fn startup(state: *mut ValidatorModuleState) {
    pgrx::info!("my validator startup");
    if state.is_null() {
        return;
    }
    let conn_params: HashMap<String, String> = unsafe { get_hba_options(state) };

    match Config::new_from_conn_params(&conn_params) {
        Ok(module_state) => unsafe {
            let boxed = Box::new(module_state);
            (*state).private_data = Box::into_raw(boxed) as *mut c_void;
        },
        Err(e) => {
            // fail to init: log it，but not FATAL to avoid let PG goto recovery mode :sob:
            pgrx::warning!("my validator startup: {}", e);
            // private_data remains null, which is handled gracefully in other functions
        }
    }
}

extern "C" fn shutdown(state: *mut ValidatorModuleState) {
    pgrx::info!("my validator shutdown");
    unsafe {
        if !(*state).private_data.is_null() {
            let _boxed: Box<Config> = Box::from_raw((*state).private_data as *mut Config);
            (*state).private_data = ptr::null_mut();
        }
    }
}

extern "C" fn validate(
    state: *const ValidatorModuleState,
    token_ptr: *const ::std::os::raw::c_char, // we don't use token in this dumb example
    role_ptr: *const ::std::os::raw::c_char,
    result: *mut ValidatorModuleResult,
) -> bool {
    // task-1: extract per-authentication parameters into Rust
    let (config, token, role) = match unsafe { get_args(state, token_ptr, role_ptr, result) } {
        Ok(args) => args,
        Err(_) => return false,
    };
    // task-2: run your validation logic in safe Rust
    let (authorized, authn_id) = safe_validate(config, &token, &role);
    // task-3: write the result back into the C structures
    unsafe { set_result(result, authorized, authn_id) };
    // Internal errors should return 'false'; this example returns 'true' for simplicity
    true
}

unsafe fn get_args(
    state: *const ValidatorModuleState,
    token_ptr: *const ::std::os::raw::c_char,
    role_ptr: *const ::std::os::raw::c_char,
    result: *mut ValidatorModuleResult,
) -> Result<(&'static Config, String, String), ()> {
    // Validate all input parameters are non-null
    if state.is_null() || result.is_null() || role_ptr.is_null() || token_ptr.is_null() {
        pgrx::warning!("validator: null state, result, role, or token pointer");
        return Err(());
    }

    // Check private_data is initialized
    if (*state).private_data.is_null() {
        pgrx::warning!("validator: null private_data");
        return Err(());
    }

    // Initialize result
    (*result).authorized = false;
    (*result).authn_id = std::ptr::null_mut();

    // Extract configuration
    let config = &*((*state).private_data as *const Config);

    // Extract token
    let token_cstr = CStr::from_ptr(token_ptr);
    let token = match token_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            pgrx::warning!("validator: invalid UTF-8 in token");
            return Err(());
        }
    };

    // Extract role
    let role_cstr = CStr::from_ptr(role_ptr);
    let role = match role_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            pgrx::warning!("validator: invalid UTF-8 in role");
            return Err(());
        }
    };

    Ok((config, token, role))
}

unsafe fn set_result(
    result: *mut ValidatorModuleResult,
    authorized: bool,
    authn_id: Option<String>,
) {
    (*result).authorized = authorized;
    if let Some(authentication_id) = authn_id {
        match CString::new(authentication_id) {
            Ok(c_string) => {
                (*result).authn_id = pstrdup(c_string.as_ptr());
            }
            Err(_) => {
                pgrx::warning!(
                    "my validator: authentication ID contains null bytes, setting to null"
                );
                (*result).authn_id = ptr::null_mut();
            }
        }
    } else {
        (*result).authn_id = ptr::null_mut();
    }
}

#[no_mangle]
pub extern "C" fn _PG_oauth_validator_module_init() -> *mut OAuthValidatorCallbacks {
    let callbacks = Box::new(OAuthValidatorCallbacks {
        magic: PG_OAUTH_VALIDATOR_MAGIC,
        startup_cb: Some(startup),
        shutdown_cb: Some(shutdown),
        validate_cb: Some(validate),
    });
    Box::into_raw(callbacks)
}
