{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE TypeSynonymInstances  #-}
module WebApi.SAML.Contract where

import           WebApi.SAML.SSOTypes
import           WebApi

data SSOServiceProvider cookie

data Saml cookie

type HomeR c = (Saml c) :// "home"
type SamlR c = (Saml c) :// "saml"
type LogoutR c = (Saml c) :// "logout"

instance WebApi (SSOServiceProvider c) where
  type Apis (SSOServiceProvider c)
    = '[Route '[POST] (SamlR c), Route '[GET] (LogoutR c)]

instance ApiContract (SSOServiceProvider c) GET (HomeR c) where
  type ApiOut GET (HomeR c) = Html
  type ApiErr GET (HomeR c) = Html
  type CookieIn GET (HomeR c) = Maybe c
  type HeaderOut GET (HomeR c) = Maybe RedirectHeader
  type ContentTypes GET (HomeR c) = '[HTML]

instance ApiContract (SSOServiceProvider c) POST (SamlR c) where
  type FormParam POST (SamlR c) = SamlResponse
  type ApiOut POST (SamlR c) = Html
  type ApiErr POST (SamlR c) = Html
  type CookieOut POST (SamlR c) = Maybe c
  type HeaderOut POST (SamlR c) = Maybe RedirectHeader
  type ContentTypes POST (SamlR c) = '[HTML]

instance ApiContract (SSOServiceProvider c) GET (LogoutR c) where
  type ApiOut GET (LogoutR c) = Html
  type ApiErr GET (LogoutR c) = Html
  type CookieIn GET (LogoutR c) = Maybe c
  type CookieOut GET (LogoutR c) = Maybe c
  type HeaderOut GET (LogoutR c) = Maybe RedirectHeader
  type ContentTypes GET (LogoutR c) = '[HTML]
