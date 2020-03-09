{-# OPTIONS_GHC -Wno-orphans        #-}
{-# LANGUAGE DuplicateRecordFields  #-}
{-# LANGUAGE OverloadedStrings      #-}

module WebApi.SAML.SSOTypes where

import           WebApi
import           GHC.Generics
import           Data.ByteString
import           Data.Trie                     as Trie

data RedirectHeader = RedirectHeader { location :: ByteString } deriving Generic
instance ToHeader RedirectHeader

instance (ToHeader a) => ToHeader (Maybe a) where
  toHeader (Just val) = toHeader val
  toHeader Nothing    = []

data SamlResponse = SamlResponse
  { samlResponse :: ByteString } deriving Generic

instance FromParam 'FormParam SamlResponse where
  fromParam pt key kvs = SamlResponse <$> fromParam pt ("SAMLResponse") sbmap
    where sbmap = submap key kvs

data SamlRequest = SamlRequest
  { samlRequest :: ByteString } deriving Generic

instance FromParam 'FormParam SamlRequest where
  fromParam pt key kvs = SamlRequest <$> fromParam pt ("SAMLRequest") sbmap
    where sbmap = submap key kvs
