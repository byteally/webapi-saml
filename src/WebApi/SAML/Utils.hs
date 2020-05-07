{-# LANGUAGE DuplicateRecordFields      #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}

module WebApi.SAML.Utils where

import           Control.Monad                  ( join )
import qualified Data.ByteString               as BS
import           Data.ByteString
import qualified Data.ByteString.Base64        as Base64
import qualified Data.ByteString.Lazy          as BSL
import qualified Data.ByteString.Lazy          as BL
import           Data.List                     as DL
import qualified Data.Map                      as M
import           Data.Text                     as T
import           Data.Time
import           Data.UUID
import           Data.UUID.V4
import           Network.URI
import           SAML2.Bindings.Identifiers
import           SAML2.Core.Assertions
import           SAML2.Core.Identifiers
import           SAML2.Core.Protocols
import qualified SAML2.Core.Protocols          as SAMLP
import           SAML2.Core.Versioning
import           SAML2.XML
import qualified SAML2.XML.Signature           as DS
import           Text.XML.HXT.DOM.TypeDefs

mkAuthnRequest :: URI -> IO AuthnRequest
mkAuthnRequest spUri = do
  now  <- getCurrentTime
  uuid <- nextRandom
  let protId = "pid-" ++ toString uuid
      spUrl  = uriScheme spUri <> maybe "" (\x -> "//" <> uriRegName x) (uriAuthority spUri)
      rat    = RequestAbstractType
        (ProtocolType protId
                      SAML20
                      (formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ" now)
                      Nothing
                      (Identified ConsentExplicit)
                      (Just (Issuer (simpleNameID NameIDFormatEntity spUrl)))
                      Nothing
                      []
                      Nothing
        )
      ar = AuthnRequest
        rat
        False
        False
        (AssertionConsumerServiceURL (Just spUri)
                                     (Just (Identified BindingHTTPPOST))
        )
        Nothing
        Nothing
        Nothing
        Nothing
        Nothing
        Nothing
        Nothing
  return ar

mkLogoutRequest :: String -> [String] -> URI -> URI -> IO LogoutRequest
mkLogoutRequest bid sessIDs idpLogoutUri spUri = do
  now  <- getCurrentTime
  uuid <- nextRandom
  let protId = "pid-" ++ toString uuid
      spUrl = uriScheme spUri <> maybe "" (\x -> "//" <> uriRegName x) (uriAuthority spUri)
      rat    = RequestAbstractType
        (ProtocolType protId
                      SAML20
                      (formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ" now)
                      (Just idpLogoutUri)
                      (Identified ConsentExplicit)
                      (Just (Issuer (simpleNameID NameIDFormatEntity spUrl)))
                      Nothing
                      []
                      Nothing
        )
      lr = LogoutRequest
        rat
        (Just (Identified LogoutReasonUser))
        Nothing -- TODO: add some time to "now"
        (NotEncrypted
          (IdentifierName
            (NameID (BaseID Nothing Nothing bid)
                    (Identified NameIDFormatUnspecified)
                    Nothing
            )
          )
        )
        sessIDs
  return lr

getAssertions :: Response -> [Assertion]
getAssertions resp =
  let fn x = case x of
        NotEncrypted y -> y
        _              -> error "Encrypted assertions not supported yet"
  in  fmap fn $ responseAssertions resp

verifySAMLAssertion :: Assertion -> IO (Maybe Bool)
verifySAMLAssertion ass = do
  let xid = assertionID ass
  DS.verifySignature mempty xid (samlToDoc ass)

verifyLogoutRequest :: SAMLP.LogoutRequest -> IO (Maybe Bool)
verifyLogoutRequest req = do
  let prot = SAMLP.requestProtocol . SAMLP.logoutRequest $ req
      xid  = SAMLP.protocolID prot
  DS.verifySignature mempty xid (samlToDoc req)

decodeLogoutReq :: Bool -> BS.ByteString -> IO SAMLP.LogoutRequest
decodeLogoutReq verf v = do
  resp <- either fail return $ xmlToSAML b
  if verf
    then do
      res <- verifyLogoutRequest resp
      case res of
        Just True -> return resp
        _         -> fail "Verification failed"
    else either fail return $ xmlToSAML b
  where b = BSL.fromStrict $ Base64.decodeLenient v

mGetNameID :: Assertion -> Maybe String
mGetNameID ass = case subjectIdentifier (assertionSubject ass) of
  Just (NotEncrypted (IdentifierName y)) -> Just (baseID . nameBaseID $ y)
  _ -> Nothing

getIDPSessionIds :: Assertion -> [String]
getIDPSessionIds ass =
  let getSig s = case s of
        StatementAuthn au ->
          maybe [] ((: []) . id) $ authnStatementSessionIndex au
        _ -> []
  in  join $ fmap getSig $ assertionStatement ass

decodeResponseToAssertion :: ByteString -> IO (Maybe Assertion)
decodeResponseToAssertion rbs =
  pure $ (either (const Nothing) id $ xmlToSAML b) >>= \resp ->
    (Just . statusCode1 . statusCode . status . response $ resp) >>= \case
      StatusSuccess -> case getAssertions resp of
        []        -> Nothing
        (ass : _) -> Just ass
      _ -> Nothing
  where b = BL.fromStrict $ Base64.decodeLenient rbs

getTextAttributes :: Assertion -> M.Map Text [Text]
getTextAttributes ass =
  M.fromList
    $ DL.foldl'
        (\b a -> case a of
          StatementAttribute attrStmt ->
            DL.foldl'
                (\b1 a1 -> case a1 of
                  NotEncrypted attr -> -- Filter NonEncrypted
                    let vals = getTextValues $ attributeValues attr
                    in  if not (DL.null vals)
                          then (T.pack $ attributeName attr, vals) : b1
                          else b1
                  _ -> b1
                )
                []
              $ attributeStatement attrStmt
          _ -> b
        )
        []
    $ assertionStatement ass
 where
  getTextValues :: [Nodes] -> [Text]
  getTextValues = DL.concat . fmap
    (DL.concat . fmap
      (DL.foldl'
        (\b2 a2 -> case a2 of
          XText t -> T.pack t : b2
          _       -> b2
        )
        []
      )
    )
