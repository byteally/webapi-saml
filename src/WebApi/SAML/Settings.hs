{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE RankNTypes            #-}
module WebApi.SAML.Settings where

import           Data.Text
import           Network.URI
import           Control.Monad.IO.Class
import           SAML2.Core.Assertions
import           Data.ByteString

data AppSettings c = AppSettings
  { spURI         :: URI
  , serverPort    :: Int
  , idpUri        :: URI
  , redirectPath  :: ByteString
  , privateKey    :: Text
  , samlHandler   :: (forall m. MonadIO m => Assertion -> m c)
  , logoutHandler :: (forall m. MonadIO m => m (Text, [Text], c))
  , homeHandler   :: (forall m. MonadIO m => Maybe c -> m (Bool))
  }
