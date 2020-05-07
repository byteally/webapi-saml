{-# OPTIONS_GHC -Wno-orphans            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DuplicateRecordFields      #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeSynonymInstances       #-}

module WebApi.SAML.Handler where

import           Control.Monad.Catch            ( MonadCatch
                                                , MonadThrow
                                                )
import           Control.Monad.Logger
import           Control.Monad.Reader
import           Crypto.PubKey.RSA.Types       as CR
import qualified Data.ByteString.Lazy.Char8    as C
import           Data.Monoid                    ( (<>) )
import qualified Data.Text                     as T
import           Data.Text.Encoding             ( encodeUtf8 )
import           Data.X509
import           Data.X509.Memory
import           Network.HTTP.Types.Status      ( badRequest400
                                                , status200
                                                , status303
                                                )
import           Network.Wai                    ( Application )
import           SAML2.Bindings.HTTPPOST
import           SAML2.Core.Protocols
import           SAML2.Core.Signature
import           SAML2.XML.Signature
import           WebApi.SAML.Contract
import           WebApi.SAML.Settings           ( AppSettings(..) )
import           WebApi.SAML.SSOTypes
import           WebApi.SAML.Utils
import           WebApi                  hiding ( err )
import           Data.Typeable

data SSOServiceProviderImpl c = SSOServiceProviderImpl (AppSettings c)

data App = App

newtype SSOServiceProviderM c a = SSOServiceProviderM (LoggingT (ReaderT (AppSettings c) IO) a)
    deriving (Functor, Applicative, Monad, MonadIO, MonadCatch, MonadThrow, MonadReader (AppSettings c), MonadLogger)

instance WebApiServer (SSOServiceProviderImpl c) where
  type HandlerM (SSOServiceProviderImpl c) = SSOServiceProviderM c
  type ApiInterface (SSOServiceProviderImpl c) = SSOServiceProvider c
  toIO (SSOServiceProviderImpl settings) (SSOServiceProviderM r) = do
    runReaderT (runStdoutLoggingT r) settings

instance ApiHandler (SSOServiceProviderImpl c) POST (SamlR c) where
  handler _ req = do
    appSetting <- ask
    let SamlResponse samlResp = formParam req

    mAss <- liftIO $ decodeResponseToAssertion $ samlResp
    liftIO $ print mAss
    case mAss of
      Just ass -> do
        smresp <- liftIO $ verifySAMLAssertion ass
        case smresp of
          Just True -> do
            ec <- liftIO . samlHandler appSetting $ ass
            case ec of
              Left  err -> respondWith badRequest400 (html err) Nothing Nothing
              Right c   -> respondWith
                status303
                (html "")
                (Just . RedirectHeader . redirectPath $ appSetting)
                (Just c)
          _ -> respondWith badRequest400 (html "Access Denied") Nothing Nothing
      _ -> respondWith badRequest400 (html "Access Denied") Nothing Nothing

instance ApiHandler (SSOServiceProviderImpl c) GET (LogoutR c) where
  handler _ req = do
    appSetting <- ask
    let mck             = cookieIn req
        x1              = encodeUtf8 $ privateKey appSetting -- Unsafe
        (PrivKeyRSA pk) = head $ readKeyFileFromMemory x1
        sk              = SigningKeyRSA . CR.KeyPair $ pk
    eRes <- liftIO $ (logoutHandler appSetting) mck
    case eRes of
      Left err -> respondWith badRequest400 (html err) Nothing Nothing
      Right (bid, sids, c) -> do
        samlReqToken <-
          liftIO $ (return . encodeValue) =<< signSAMLProtocol sk =<< fmap
            RequestLogoutRequest
            (mkLogoutRequest (T.unpack bid)
                             (fmap T.unpack sids)
                             (idpUri appSetting)
                             (spURI appSetting)
            )

        respondWith
          status200
          (html (htmlBdy (C.fromStrict samlReqToken) (idpUri appSetting)))
          Nothing
          (Just c)
   where
      -- replace HTTP POST with HTTP Redirect
    htmlBdy x idp =
      "<form id=\"saml-form\" method=\"POST\" action=\""
        <> C.pack (show idp)
        <> "\"><input name=\"SAMLRequest\" type='hidden' value=\""
        <> x
        <> "\" /></form><script>document.getElementById(\"saml-form\").submit();</script>"

instance ApiHandler (SSOServiceProviderImpl c) GET (HomeR c) where
  handler _ req = do
    appSetting <- ask
    let mck = cookieIn req

    isLoggedIn <- liftIO $ (homeHandler appSetting) mck

    case isLoggedIn of
      True -> respondWith status303
                          (html "")
                          (Just . RedirectHeader . redirectPath $ appSetting)
                          ()
      _ -> do
        samlReqToken <- liftIO $ (return . encodeValue) =<< mkAuthnRequest
          (spURI appSetting)
        respondWith
          status200
          (html (htmlBdy (C.fromStrict samlReqToken) (idpUri appSetting)))
          Nothing
          ()
   where
    htmlBdy x idp =
      "<form id=\"saml-form\" method=\"POST\" action=\""
        <> C.pack (show idp)
        <> "\"><input name=\"SAMLRequest\" type='hidden' value=\""
        <> x
        <> "\" /> </form><script>document.getElementById(\"saml-form\").submit();</script>"

ssoSPApp
  :: (Typeable c, ToParam 'Cookie c, FromParam 'Cookie c)
  => AppSettings c
  -> Application
ssoSPApp settings = serverApp serverSettings (SSOServiceProviderImpl settings)

instance ParamErrToApiErr Html where
  toApiErr _ = html "Params Failed"
