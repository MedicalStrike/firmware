#pragma once
#include "ProtobufModule.h"
#include "meshtastic/x3dh.pb.h"

#define MAX_NUM_OTPKS 10

static constexpr const char *x3dhDatabaseFilename = "/prefs/X3DH_DB.proto";

static const char *x3dhHkdfInfo = "Meshtastic X3DH";

static const uint8_t ZERO[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t HASH_PADDING[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * Extended Triple Diffie-Hellman for Meshtastic
 */
class X3dhModule : public ProtobufModule<meshtastic_X3DHMessage>
{
  public:
    X3dhModule() : ProtobufModule("x3dh", meshtastic_PortNum_PRIVATE_APP, &meshtastic_X3DHMessage_msg)
    {
        ourPortNum = meshtastic_PortNum_PRIVATE_APP;
        if (checkDatabaseExists()) {
            loadX3dhDb();
        } else {
            initX3dhDb();
        }
    }

  protected:
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        return p->decoded.portnum == ourPortNum ||
               (p->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP && isToUs(p)); // meshtastic_PortNum_NODEINFO_APP;
    }

    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_X3DHMessage *decoded) override;

    virtual meshtastic_MeshPacket *allocReply() override;

  private:
    void loadX3dhDb();

    void initX3dhDb();

    void genOTPK(uint32_t otpkId, uint8_t privKey[32]);

    void getAndRegenOTPK(uint32_t *keyId, uint8_t otpkPrivKey[32]);

    size_t getMaxPreKeyBundleAllocatedSize();

    bool checkDatabaseExists();

    bool saveX3dhDatabaseToDisk();

    meshtastic_X3DHMessage x3dhReply;
};
extern X3dhModule *x3dhModule;