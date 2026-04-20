#include "X3dhModule.h"
#include "Crypto.h"
#include "CryptoEngine.h"
#include "Curve25519.h"
#include "FSCommon.h"
#include "HKDF.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "RNG.h"
#include "SHA512.h"
#include "SPILock.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include "meshtastic/x3dh_payload.pb.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include <string>

meshtastic_PreKeyBundle x3dhDB;
std::vector<meshtastic_OneTimePreKey> *otpks;

bool X3dhModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_X3DHMessage *decoded)
{
    bool toReturn = false;
    LOG_DEBUG("Starting to process message with PortNum %d", mp.decoded.portnum);
    // if (decoded == NULL && mp.which_payload_variant == meshtastic_PortNum_NODEINFO_APP) {
    //     meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
    //     if (node == NULL) {
    //         LOG_WARN("Node %s not found in Database, aborting.", node->num);
    //     } else {
    //         bool usesX3dh = node->user.has_x3dh_shared_key;
    //         if (usesX3dh) {
    //             LOG_INFO("X3DH-Agreement already finished for Node %s", node->num);
    //         } else {
    //             if (!node->user.has_x3dh_state || node->user.x3dh_state == meshtastic_X3DHState_X3DH_NOT_STARTED) {
    //                 meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
    //                 meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
    //                 initBundle.node_num = mp.from;
    //                 memcpy(initBundle.public_key, mp.public_key.bytes, 32);
    //                 uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
    //                 pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
    //                                    &initBundle);
    //                 memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
    //                 auto x3dhMessage = allocDataProtobuf(init);
    //                 x3dhMessage->to = mp.from;
    //                 x3dhMessage->pki_encrypted = true;
    //                 memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
    //                 x3dhMessage->decoded.want_response = true;
    //                 node->user.x3dh_state = meshtastic_X3DHState_BUNDLE_REQUESTED;
    //                 service->sendToMesh(x3dhMessage);
    //             } else {
    //                 LOG_INFO("X3DH-Agreement already started for Node %s", node->num);
    //             }
    //         }
    //     }
    if (mp.decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP) {
        char messageArray[10] = "startX3DH";
        auto &p = mp.decoded;
        LOG_INFO("Received text msg from=0x%0x, id=0x%x, msg=%.*s", mp.from, mp.id, p.payload.size, p.payload.bytes);
        if (memcmp(messageArray, p.payload.bytes, p.payload.size)) {
            LOG_INFO("Message from 0x%0x does not contain the keyword to start an X3DH-agreement.", mp.from);
        } else {
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            bool usesX3dh = node->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK;
            LOG_INFO("Node has state %d", node->user.x3dh_state);
            if (usesX3dh) {
                if (node->user.x3dh_state == meshtastic_X3DHState_X3DH_NOT_STARTED) {
                    meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                    meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
                    initBundle.node_num = mp.from;
                    memcpy(initBundle.public_key, mp.public_key.bytes, 32);
                    uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
                    pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
                                       &initBundle);
                    memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
                    auto x3dhMessage = allocDataProtobuf(init);
                    x3dhMessage->to = mp.from;
                    x3dhMessage->pki_encrypted = true;
                    memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                    x3dhMessage->decoded.want_response = true;
                    x3dhMessage->want_ack = true;
                    node->user.x3dh_state = meshtastic_X3DHState_BUNDLE_REQUESTED;
                    service->sendToMesh(x3dhMessage);
                } else {
                    LOG_INFO("X3DH-Agreement already started for Node 0x%0x", node->num);
                }
            } else {
                LOG_INFO("X3DH-Agreement already finished for Node 0x%0x", node->num);
            }
            toReturn = true;
        }
    } else {
        switch (decoded->type) {
        case meshtastic_X3DHMessageType_REQUEST_BUNDLE: {
            x3dhReply = meshtastic_X3DHMessage_init_default;
            meshtastic_RequestBundle bundle;
            memset(&bundle, 0, sizeof(bundle));
            if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_RequestBundle_fields,
                                     &bundle)) {
                if (x3dhDB.node_num == myNodeInfo.my_node_num) {
                    x3dhReply.type = meshtastic_X3DHMessageType_RESPONSE_BUNDLE;
                    meshtastic_PreKeyBundle response;
                    response.node_num = x3dhDB.node_num;
                    memcpy(response.identity_key, x3dhDB.identity_key, 32);
                    uint8_t tempPubKey[32] = {0};
                    crypto->regeneratePublicKey(tempPubKey, x3dhDB.signed_pre_key);
                    memcpy(response.signed_pre_key, tempPubKey, 32);
                    clean(tempPubKey);
                    memcpy(response.pre_key_signature, x3dhDB.pre_key_signature, 64);
                    meshtastic_OneTimePreKey otpkResponse = meshtastic_OneTimePreKey_init_default;
                    for (auto iterator = otpks->begin(); iterator != otpks->end(); ++iterator) {
                        meshtastic_OneTimePreKey current = *iterator;
                        if (!current.has_node_num) {
                            otpkResponse.id = current.node_num;
                            current.node_num = mp.from;
                            crypto->regeneratePublicKey(tempPubKey, current.key);
                            memcpy(otpkResponse.key, tempPubKey, 32);
                            clean(tempPubKey);
                            break;
                        }
                    }
                    if (otpkResponse.id != 0) {
                        response.one_time_pre_keys = std::vector<meshtastic_OneTimePreKey>(1);
                        response.one_time_pre_keys.insert(response.one_time_pre_keys.begin(), otpkResponse);
                        pb_encode_to_bytes(x3dhReply.payload.bytes, getSinglePreKeyBundleAllocatedSize(),
                                           meshtastic_PreKeyBundle_fields, &response);
                    } else {
                        LOG_WARN("No free one-time pre-keys found, aborting X3DH-agreement");
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    }
                } else {
                    meshtastic_NodeInfoLite *server = nodeDB->getMeshNode(x3dhDB.node_num);
                    x3dhReply.type = meshtastic_X3DHMessageType_EXTERNAL_BUNDLE;
                    meshtastic_RequestBundle externalBundle = meshtastic_RequestBundle_init_default;
                    externalBundle.node_num = x3dhDB.node_num;
                    memcpy(externalBundle.public_key, &server->user.public_key, 32);
                    pb_encode_to_bytes(x3dhReply.payload.bytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
                                       &externalBundle);
                }
            } else {
                LOG_WARN("Payload protobuf decode failed. Invalid payload type for REQUEST_BUNDLE");
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            }
            break;
        }

        case meshtastic_X3DHMessageType_EXTERNAL_BUNDLE: {
            meshtastic_RequestBundle bundle;
            memset(&bundle, 0, sizeof(bundle));
            meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
            NodeNum to;
            if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_RequestBundle_fields,
                                     &bundle)) {
                to = bundle.node_num;
                meshtastic_NodeInfoLite *serverNode = nodeDB->getMeshNode(to);
                if (serverNode == NULL) {
                    LOG_WARN("No node found for ID %s", to);
                    break;
                } else {
                    meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
                    if (memcmp(bundle.public_key, serverNode->user.public_key.bytes, 32)) {
                        meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
                        initBundle.node_num = mp.from;
                        memcpy(initBundle.public_key, mp.public_key.bytes, 32);
                        uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
                        pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
                                           &initBundle);
                        memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
                        LOG_INFO("Sending RequestBundle to Server %s for Pre-Key-Bundle for Node %s", to, mp.from);
                        meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
                        node->user.x3dh_state = meshtastic_X3DHState_EXTERNAL_BUNDLE_REQUESTED;
                    } else {
                        LOG_WARN("Server public key mismatch, aborting X3DH handshake");
                        init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        to = mp.from;
                        // Reset state so we can try again on next NodeInfo-packet
                        node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    }
                }
            } else {
                LOG_WARN("Payload protobuf decode failed. Invalid payload type for EXTERNAL_BUNDLE");
                init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                to = mp.from;
            }
            auto x3dhServerMessage = allocDataProtobuf(init);
            x3dhServerMessage->pki_encrypted = true;
            memcpy(x3dhServerMessage->public_key.bytes, crypto->public_key, x3dhServerMessage->public_key.size);
            x3dhServerMessage->to = to;
            service->sendToMesh(x3dhServerMessage);
            break;
        }

        case meshtastic_X3DHMessageType_RESPONSE_BUNDLE: {
            x3dhReply = meshtastic_X3DHMessage_init_default;
            NodeNum to = mp.from;
            meshtastic_PreKeyBundle preKeyBundle;
            if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_PreKeyBundle_fields,
                                     &preKeyBundle)) {
                meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(preKeyBundle.node_num);
                if (memcmp(preKeyBundle.identity_key, &node->user.public_key, 32)) {
                    std::vector<meshtastic_OneTimePreKey> tempKeyVector = preKeyBundle.one_time_pre_keys;
                    if (tempKeyVector.size() > 0) {
                        HKDF<SHA512> hkdf;
                        uint8_t ephermalPrivKey[32] = {0};
                        uint8_t ephermalPubKey[32] = {0};
                        uint8_t DH1[32] = {0};
                        uint8_t DH2[32] = {0};
                        uint8_t DH3[32] = {0};
                        uint8_t DH4[32] = {0};
                        uint8_t AD[64] = {0};
                        uint8_t KM[160] = {0};
                        uint8_t SK[32] = {0};
                        uint8_t futureSecret[32] = {0};
                        uint8_t nonceExtra[4] = {0};
                        Curve25519::dh1(ephermalPubKey, ephermalPrivKey);
                        meshtastic_OneTimePreKey singleOneTimePreKey = tempKeyVector.front();
                        memcpy(DH1, preKeyBundle.signed_pre_key, 32);
                        memcpy(DH2, preKeyBundle.identity_key, 32);
                        memcpy(DH3, preKeyBundle.signed_pre_key, 32);
                        memcpy(DH4, singleOneTimePreKey.key, 32);
                        memcpy(AD, x3dhDB.identity_key, 32);
                        memcpy(AD + 32, &mp.public_key, 32);
                        memcpy(KM, HASH_PADDING, 32);
                        CryptRNG.rand(futureSecret, 32);
                        CryptRNG.rand(nonceExtra, 4);
                        if (!crypto->setDHPublicKey(DH1)) {
                            x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                            break;
                        } else {
                            memcpy(KM + 32, DH1, 32);
                            clean(DH1);
                        }
                        if (!Curve25519::dh2(DH2, ephermalPrivKey)) {
                            x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                            break;
                        } else {
                            memcpy(KM + 64, DH2, 32);
                            clean(DH2);
                        }
                        if (!Curve25519::dh2(DH3, ephermalPrivKey)) {
                            x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                            break;
                        } else {
                            memcpy(KM + 96, DH3, 32);
                            clean(DH3);
                        }
                        if (!Curve25519::dh2(DH4, ephermalPrivKey)) {
                            x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                            break;
                        } else {
                            memcpy(KM + 128, DH4, 32);
                            clean(DH4);
                        }
                        hkdf.setKey(KM, sizeof(KM));
                        hkdf.extract(SK, 32, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                        hkdf.clear();
                        clean(KM);
                        uint8_t nonce[16] = {0};
                        hkdf.setKey(nonceExtra, 4);
                        hkdf.extract(nonce, 16, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                        hkdf.clear();
                        clean(nonceExtra);
                        uint8_t cyphertext[40] = {0};
                        if (aes_ccm_ae(SK, 32, nonce, 8, futureSecret, 32, AD, 64, cyphertext, cyphertext + 32)) {
                            meshtastic_InitialMessage initMessage = meshtastic_InitialMessage_init_default;
                            initMessage.otpk_id = singleOneTimePreKey.id;
                            memcpy(initMessage.ephermal_key, ephermalPubKey, 32);
                            memcpy(initMessage.initial_cyphertext.bytes, cyphertext, 40);
                            size_t initMessageSize;
                            pb_get_encoded_size(&initMessageSize, meshtastic_InitialMessage_fields, &initMessage);
                            uint8_t initialMessageBytes[initMessageSize] = {0};
                            pb_encode_to_bytes(initialMessageBytes, initMessageSize, meshtastic_InitialMessage_fields,
                                               &initMessage);
                            memcpy(x3dhReply.payload.bytes, initialMessageBytes, sizeof(initialMessageBytes));
                            clean(initialMessageBytes, initMessageSize);
                            node->user.x3dh_state = meshtastic_X3DHState_INIT_SENT;
                            LOG_INFO("Initial message sent to node %s", node->num);
                            printBytes("Plaintext key: ", futureSecret, 32);
                            printBytes("Encrypted key: ", cyphertext, 40);
                        } else {
                            LOG_WARN("Authenticated encryption of initial message failed, aborting X3DH handshake");
                            x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                            to = preKeyBundle.node_num;
                            // Reset state so we can try again
                            node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                        }
                        clean(futureSecret);
                        clean(SK);
                        clean(nonce);
                        clean(cyphertext);
                        clean(ephermalPrivKey);
                        clean(ephermalPubKey);
                        clean(singleOneTimePreKey);
                        tempKeyVector.clear();
                    } else {
                        LOG_WARN("No one-time pre-key provided, aborting X3DH handshake");
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        to = preKeyBundle.node_num;
                        // Reset state so we can try again
                        node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    }
                } else {
                    LOG_WARN("Node public key mismatch, aborting X3DH handshake");
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    to = preKeyBundle.node_num;
                    // Reset state so we can try again
                    node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                }
            }
            clean(preKeyBundle);
            break;
        }

        case meshtastic_X3DHMessageType_INITIAL_MESSAGE: {
            x3dhReply = meshtastic_X3DHMessage_init_default;
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            meshtastic_InitialMessage initialMessage;
            memset(&initialMessage, 0, sizeof(initialMessage));
            if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_InitialMessage_fields,
                                     &initialMessage)) {
                HKDF<SHA512> hkdf;
                uint8_t DH1[32] = {0};
                uint8_t DH2[32] = {0};
                uint8_t DH3[32] = {0};
                uint8_t DH4[32] = {0};
                uint8_t AD[64] = {0};
                uint8_t KM[160] = {0};
                uint8_t SK[32] = {0};
                memcpy(DH1, &mp.public_key, 32);
                memcpy(DH2, initialMessage.ephermal_key, 32);
                memcpy(DH3, initialMessage.ephermal_key, 32);
                memcpy(DH4, initialMessage.ephermal_key, 32);
                memcpy(AD, &mp.public_key, 32);
                memcpy(AD + 32, x3dhDB.identity_key, 32);
                memcpy(KM, HASH_PADDING, 32);
                if (!Curve25519::dh2(DH1, x3dhDB.signed_pre_key)) {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    break;
                } else {
                    memcpy(KM + 32, DH1, 32);
                    clean(DH1);
                }
                if (!crypto->setDHPublicKey(DH2)) {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    break;
                } else {
                    memcpy(KM + 64, DH2, 32);
                    clean(DH2);
                }
                if (!Curve25519::dh2(DH3, x3dhDB.signed_pre_key)) {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    break;
                } else {
                    memcpy(KM + 96, DH3, 32);
                    clean(DH3);
                }
                uint8_t otpkPrivKey = {0};
                getAndRegenOTPK(&initialMessage.otpk_id, &otpkPrivKey);
                if (&otpkPrivKey == ZERO) {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    break;
                }
                if (!Curve25519::dh2(DH4, &otpkPrivKey)) {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    break;
                } else {
                    memcpy(KM + 128, DH4, 32);
                    clean(DH4);
                }
                hkdf.setKey(KM, sizeof(KM));
                hkdf.extract(SK, 32, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                hkdf.clear();
                clean(KM);
                uint8_t nonce[16] = {0};
                hkdf.setKey(&mp.channel, 4);
                hkdf.extract(nonce, 16, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                hkdf.clear();
                uint8_t receivedSecret[32] = {0};
                uint8_t authTag[8] = {0};
                memcpy(authTag, &initialMessage.initial_cyphertext.bytes + initialMessage.initial_cyphertext.size - 8, 8);
                if (aes_ccm_ad(SK, 32, nonce, 8, initialMessage.initial_cyphertext.bytes,
                               initialMessage.initial_cyphertext.size - 8, AD, 64, authTag, receivedSecret)) {

                    memcpy(node->user.x3dh_shared_key.bytes, receivedSecret, 32);
                    printBytes("Plaintext key: ", receivedSecret, 32);
                    printBytes("Encrypted key: ", initialMessage.initial_cyphertext.bytes, 40);
                    node->user.x3dh_shared_key.size = 32;
                    node->user.x3dh_state = meshtastic_X3DHState_PROTOCOL_SET;
                    node->bitfield |= NODEINFO_BITFIELD_USES_X3DH_MASK;
                    x3dhReply.type = meshtastic_X3DHMessageType_PROTOCOL_SWITCH;
                    x3dhReply.continue_protocol = meshtastic_X3DHProtocol_X3DH_SECRET;
                    LOG_INFO("X3DH-Agreement with node %s completed", node->num);
                } else {
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    LOG_WARN("Decryption unsuccessful, aborting X3dh-agreement with node %s", node->num);
                }
                clean(SK);
                clean(receivedSecret);
                clean(authTag);
            }
            break;
        }

        case meshtastic_X3DHMessageType_PROTOCOL_SWITCH: {
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            if (node->user.x3dh_state == meshtastic_X3DHState_INIT_SENT && node->user.has_x3dh_shared_key) {
                LOG_INFO("Confirmed usage of X3DH-Secret for future direct messages with node %s", mp.from);
                node->bitfield |= NODEINFO_BITFIELD_USES_X3DH_MASK;
                node->user.x3dh_state = meshtastic_X3DHState_PROTOCOL_SET;
            } else if (node->user.x3dh_state == meshtastic_X3DHState_PROTOCOL_SET) {
                LOG_INFO("Post-X3DH-Protocol already set, no change");
            } else {
                LOG_INFO("X3DH-Agreement not finished, protocol won't be set");
            }
            break;
        }

        case meshtastic_X3DHMessageType_X3DH_ERROR: {
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            if ((node->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK) &&
                node->user.x3dh_state == meshtastic_X3DHState_PROTOCOL_SET) {
                LOG_WARN("Possible X3DH-Downgrade-Attack or misguided packet. X3DH-State won't be reset");
            } else if (node->user.x3dh_state == meshtastic_X3DHState_PROTOCOL_SET) {
                LOG_WARN("Node already uses post-X3DH-protocol, misguided packet or possible attack");
            } else if (decoded->has_payload) {
                meshtastic_RequestBundle bundle;
                memset(&bundle, 0, sizeof(bundle));
                if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_RequestBundle_fields,
                                         &bundle)) {
                    meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(bundle.node_num);
                    LOG_WARN("Retrieval of pre-key-bundle of node %s failed, aborting X3DH-Handshake", bundle.node_num);
                    node->user.has_x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                    init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    auto x3dhMessage = allocDataProtobuf(init);
                    x3dhMessage->pki_encrypted = true;
                    memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                    x3dhMessage->to = bundle.node_num;
                    service->sendToMesh(x3dhMessage);
                }
            }
            break;
        }

        default: {
            break;
        }
        }
        toReturn = true;
    }
    return toReturn;
}

meshtastic_MeshPacket *X3dhModule::allocReply()
{
    auto x3dhMessage = allocDataProtobuf(x3dhReply);
    x3dhMessage->decoded.portnum = ourPortNum;
    memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
    x3dhMessage->pki_encrypted = true;
    return x3dhMessage;
}

void X3dhModule::loadX3dhDb()
{
    LOG_INFO("Loading X3DH-Database from file %s", x3dhDatabaseFilename);
    LOG_INFO("Calculated size: %d", getMaxPreKeyBundleAllocatedSize());
    if (nodeDB->loadProto(x3dhDatabaseFilename, getMaxPreKeyBundleAllocatedSize(), sizeof(meshtastic_PreKeyBundle),
                          &meshtastic_PreKeyBundle_msg, &x3dhDB) != LoadFileResult::LOAD_SUCCESS) {
        LOG_WARN("Could not load X3DH-DB from disk, creating new one");
        initX3dhDb();
    } else {
        size_t preKeyBundleDatabaseSize;
        pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyBundle_fields, &x3dhDB);
        LOG_INFO("Real size: %d", preKeyBundleDatabaseSize);
    }
    otpks = &x3dhDB.one_time_pre_keys;
}

void X3dhModule::initX3dhDb()
{
    LOG_DEBUG("Installing default X3DH-Database");
    x3dhDB.node_num = myNodeInfo.my_node_num;
    memcpy(x3dhDB.identity_key, crypto->public_key, 32);
    uint8_t tempPrivKey[32] = {0};
    uint8_t tempPubKey[32] = {0};
    Curve25519::dh1(tempPubKey, tempPrivKey);
    memcpy(x3dhDB.signed_pre_key, tempPrivKey, 32);
    uint8_t tempSig[64] = {0};
    crypto->xeddsa_sign(tempPubKey, 32, tempSig);
    memcpy(x3dhDB.pre_key_signature, tempSig, 64);
    x3dhDB.one_time_pre_keys = std::vector<meshtastic_OneTimePreKey>(MAX_NUM_OTPKS);
    otpks = &x3dhDB.one_time_pre_keys;
    for (size_t i = 0; i < MAX_NUM_OTPKS; i++) {
        meshtastic_OneTimePreKey otpk = otpks->at(i);
        genOTPK(otpk.id, otpk.key);
    }
    clean(tempPrivKey);
    clean(tempPubKey);
    clean(tempSig);
    bool result = saveX3dhDatabaseToDisk();
}

void X3dhModule::genOTPK(uint32_t otpkId, uint8_t privKey[32])
{
    uint8_t tempPubKey[32] = {0};
    uint8_t OTPKNum[4] = {0};
    Curve25519::dh1(tempPubKey, privKey);
    CryptRNG.rand(OTPKNum, 4);
    memcpy(&otpkId, OTPKNum, 4);
    clean(tempPubKey);
}

void X3dhModule::getAndRegenOTPK(uint32_t *keyId, uint8_t otpkPrivKey[32])
{
    for (auto iterator = otpks->begin(); iterator != otpks->end(); ++iterator) {
        meshtastic_OneTimePreKey tempOtpks = *iterator;
        if (&tempOtpks.id == keyId) {
            memcpy(otpkPrivKey, tempOtpks.key, 32);
            otpks->erase(iterator);
            if (x3dhDB.node_num ==
                myNodeInfo.my_node_num) { // Only regenerate one-time pre-key if we don't store bundle on external server
                meshtastic_OneTimePreKey otpk = meshtastic_OneTimePreKey_init_default;
                genOTPK(otpk.id, otpk.key);
                otpks->insert(iterator, otpk);
            }
        }
    }
}

size_t X3dhModule::getMaxPreKeyBundleAllocatedSize()
{
    meshtastic_PreKeyBundle emptyPreKeyBundle;
    size_t preKeyBundleDatabaseSize;
    pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyBundle_fields, &emptyPreKeyBundle);
    return preKeyBundleDatabaseSize + (MAX_NUM_OTPKS * meshtastic_OneTimePreKey_size);
}

size_t X3dhModule::getSinglePreKeyBundleAllocatedSize()
{
    meshtastic_PreKeyBundle emptyPreKeyBundle;
    size_t preKeyBundleDatabaseSize;
    pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyBundle_fields, &emptyPreKeyBundle);
    return preKeyBundleDatabaseSize + (meshtastic_OneTimePreKey_size);
}

bool X3dhModule::checkDatabaseExists()
{
    spiLock->lock();
    bool x3dhDatabaseExists = FSCom.exists(x3dhDatabaseFilename);
    spiLock->unlock();
    return x3dhDatabaseExists;
}

bool X3dhModule::saveX3dhDatabaseToDisk()
{
    size_t preKeyBundleDatabaseSize;
    pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyBundle_fields, &x3dhDB);
    LOG_INFO("X3DH-DB size before saving: %d", preKeyBundleDatabaseSize);
    return nodeDB->saveProto(x3dhDatabaseFilename, preKeyBundleDatabaseSize, &meshtastic_PreKeyBundle_msg, &x3dhDB, false);
}

bool meshtastic_PreKeyBundle_callback(pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_iter_t *field)
{
    if (ostream) {
        std::vector<meshtastic_OneTimePreKey> const *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;
        for (auto item : *vec) {
            if (!pb_encode_tag_for_field(ostream, field))
                return false;
            pb_encode_submessage(ostream, meshtastic_OneTimePreKey_fields, &item);
        }
    }
    if (istream) {
        meshtastic_OneTimePreKey otpk; // this gets good data
        std::vector<meshtastic_OneTimePreKey> *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;

        if (istream->bytes_left && pb_decode(istream, meshtastic_OneTimePreKey_fields, &otpk))
            vec->push_back(otpk);
    }
    return true;
}

bool meshtastic_OneTimePreKeyBundle_callback(pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_iter_t *field)
{
    if (ostream) {
        std::vector<meshtastic_OneTimePreKey> const *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;
        for (auto item : *vec) {
            if (!pb_encode_tag_for_field(ostream, field))
                return false;
            pb_encode_submessage(ostream, meshtastic_OneTimePreKey_fields, &item);
        }
    }
    if (istream) {
        meshtastic_OneTimePreKey otpk; // this gets good data
        std::vector<meshtastic_OneTimePreKey> *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;

        if (istream->bytes_left && pb_decode(istream, meshtastic_OneTimePreKey_fields, &otpk))
            vec->push_back(otpk);
    }
    return true;
}