use crate::config::Config;
use crate::validator::safe_validate;
use pgrx::pg_sys::pstrdup;
use std::ffi::{c_void, CStr, CString};
use std::ptr;

#[repr(C)]
pub struct ValidatorModuleState {
    pub sversion: ::std::os::raw::c_int,
    pub private_data: *mut ::std::os::raw::c_void,
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
pub const PG_OAUTH_VALIDATOR_MAGIC: u64 = 0x20250220;

extern "C" fn startup(state: *mut ValidatorModuleState) {
    if state.is_null() {
        return;
    }

    let config =  Config::new_from_env();
    let boxed = Box::new(config);
    unsafe {
        (*state).private_data = Box::into_raw(boxed) as *mut c_void;
    }
}

extern "C" fn shutdown(state: *mut ValidatorModuleState) {
    unsafe {
        if !(*state).private_data.is_null() {
            let _boxed: Box<Config> = Box::from_raw((*state).private_data as *mut Config);
            (*state).private_data = ptr::null_mut();
        }
    }
}

extern "C" fn validate(
    state: *const ValidatorModuleState,
    token_ptr: *const ::std::os::raw::c_char,
    role_ptr: *const ::std::os::raw::c_char,
    result: *mut ValidatorModuleResult,
) -> bool {
    let (config, token, role) = match unsafe { get_args(state, token_ptr, role_ptr, result) } {
        Ok(args) => args,
        Err(_) => return false,
    };
    let (authorized, authn_id) = safe_validate(config, &token, &role);
    unsafe { set_result(result, authorized, authn_id) };
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
    (*result).authn_id = ptr::null_mut();

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
