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
import qualified Data.ByteString.Lazy          as BSL

data AppSettings c = AppSettings
  { spURI         :: URI
  , idpUri        :: URI
  , redirectPath  :: ByteString
  , privateKey    :: Text
  , samlHandler   :: (forall m. MonadIO m => Assertion -> m (Either BSL.ByteString c))
  , logoutHandler :: (forall m. MonadIO m => Maybe c -> m (Either BSL.ByteString (Text, [Text], c)))
  , homeHandler   :: (forall m. MonadIO m => Maybe c -> m (Bool))
  }
