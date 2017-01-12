port module PortsAuth exposing (..)


port auth_SignUp :
    { username : String
    , password : String
    }
    -> Cmd msg


port auth_Confirm :
    { username : String
    }
    -> Cmd msg


port auth_LogIn :
    { username : String
    , password : String
    }
    -> Cmd msg


port auth_LogOut :
    { username : String
    }
    -> Cmd msg


type alias JSONResult =
    String


type alias PortError msg =
    (String -> msg) -> Sub msg


port auth_SignUpError : PortError msg


type alias SignUpSuccess =
    { result : JSONResult
    }


port auth_SignUpSuccess : (SignUpSuccess -> msg) -> Sub msg


port auth_ConfirmError : PortError msg


type alias ConfirmSuccess =
    { result : JSONResult
    }


port auth_ConfirmSuccess : (ConfirmSuccess -> msg) -> Sub msg


port auth_LogInError : PortError msg


type alias LoginSuccess =
    { result : JSONResult
    }


port auth_LogInSuccess : (LoginSuccess -> msg) -> Sub msg


port auth_LogOutError : PortError msg


type alias LogOutSuccess =
    { result : JSONResult
    }


port auth_LogOutSuccess : (LogOutSuccess -> msg) -> Sub msg
