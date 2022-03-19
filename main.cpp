#include <iostream>
#include <string>
#include <signal_protocol.h>
#include <key_helper.h>
#include <session_builder.h>
#include <session_cipher.h>
#include <protocol.h>
#include <chrono>
#include <vector>
#include <array>
#include <cassert>
#include <session_pre_key.h>
#include <key_helper.h>
#include <curve.h>
#include <random>
#include "my_test_common.hpp"

uint8_t get_hex_val(char c)
{
    if (c >= '0' && c <= '9')
    {
        return static_cast<uint8_t>(c - '0');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    return static_cast<uint8_t>(c - 'A' + 10);
}

std::vector<uint8_t> from_base_16(const std::string &s)
{
    std::vector<uint8_t> result;
    result.resize(s.size() / 2);

    static const std::array<char, 16> HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (size_t i = 0; i < s.size() / 2; i++)
    {
        uint8_t a = get_hex_val(s[i * 2]);
        uint8_t b = get_hex_val(s[i * 2 + 1]);
        result[i] = (a << 4) | b;
    }
    return result;
}

std::string to_base_16(const std::vector<uint8_t> &data)
{
    static const std::array<char, 16> HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string result;
    for (size_t i = 0; i < data.size(); i++)
    {
        result += HEX[(data[i] & 0xf0) >> 4];
        result += HEX[(data[i] & 0x0f)];
    }

    return result;
}

int test_random_generator(uint8_t *data, size_t len, void *user_data)
{
    static std::random_device dev;
    for(size_t i = 0; i< len; i++) {
        data[i] = dev();
    }
    return 0;
}

int main(void)
{
    // Init:
    signal_context *global_context;
    signal_context_create(&global_context, nullptr);
    // setup_crypot_ctx(global_context);
    signal_crypto_provider provider{};
    provider.random_func = &test_random_generator;
    signal_context_set_crypto_provider(global_context, &provider);
    // signal_context_set_locking_functions(global_context, lock_function, unlock_function);
    
    std::vector<uint8_t> ident_priv = from_base_16("1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93");
    std::string st = to_base_16(ident_priv);
    ec_private_key *ident_private_key = nullptr;
    int result = curve_decode_private_point(&ident_private_key, ident_priv.data(), ident_priv.size(), global_context);
    assert(result == 0);

    std::vector<uint8_t> pre_priv = from_base_16("181c0ed79c361f2d773f3aa8d5934569395a1c1b4a8514d140a7dcde92688579");
    ec_private_key *pre_private_key = nullptr;
    result = curve_decode_private_point(&pre_private_key, pre_priv.data(), pre_priv.size(), global_context);
    assert(result == 0);
    std::vector<uint8_t> pre_pub = from_base_16("05b30aad2471f7186bdb34951747cf81a67245144260e20ffe5bf7748202d6572c");
    ec_public_key *pre_public_key = nullptr;
    result = curve_decode_point(&pre_public_key, pre_pub.data(), pre_pub.size(), global_context);
    assert(result == 0);

    signal_buffer *public_buf = nullptr;
    result = ec_public_key_serialize(&public_buf, pre_public_key);
    assert(result == 0);

    signal_buffer *signature_buf = nullptr;
    curve_calculate_signature(global_context,
                              &signature_buf,
                              ident_private_key,
                              signal_buffer_data(public_buf),
                              signal_buffer_len(public_buf));
    std::string sig_str = to_base_16(std::vector<uint8_t>(signal_buffer_data(signature_buf), signal_buffer_data(signature_buf) + signal_buffer_len(signature_buf)));

    /*session_signed_pre_key *signed_pre_key;
    result = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, 5, std::chrono::system_clock::now().time_since_epoch().count(), global_context);
    assert(result == 0);
    const uint8_t *buf = session_signed_pre_key_get_signature(signed_pre_key);
    size_t buf_len = session_signed_pre_key_get_signature_len(signed_pre_key);*/

    // std::string s = to_base_16(std::vector<uint8_t>(signature_buf, buf + buf_len));

    // Generate keys:
    // ratchet_identity_key_pair *identity_key_pair;
    uint32_t registration_id;
    signal_protocol_key_helper_pre_key_list_node *pre_keys_head;

    // signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, global_context);
    signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context);
    signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, 1, 100, global_context);

    /* Create the test data stores */
    signal_protocol_store_context *store_context = 0;
    setup_test_store_context(&store_context, global_context);

    std::cout << "Setup done\n";

    /* Instantiate a session_builder for a recipient address. */
    signal_protocol_address address = {
        "test1@xmpp.uwpx.org", 12, 1};
    session_builder *builder;
    session_builder_create(&builder, store_context, &address, global_context);

    uint32_t reg_id = 0;
    signal_protocol_identity_get_local_registration_id(store_context, &reg_id);

    session_pre_key_bundle *retrieved_bundle = nullptr;
    result = session_pre_key_bundle_create(&retrieved_bundle,
                                           reg_id,
                                           1,        /* device ID */
                                           31337,    /* pre key ID */
                                           nullptr,  // ec_key_pair_get_public(bob_pre_key_pair),
                                           1,        /* signed pre key ID */
                                           nullptr,  /* signature */
                                           0,        /* signature length */
                                           0,        /* signed pre key */
                                           nullptr); // ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    if (result != 0)
    {
        std::cerr << "Failed to build pre key bundle\n";
        exit(1);
    }

    /* Build a session with a pre key retrieved from the server. */
    session_builder_process_pre_key_bundle(builder, retrieved_bundle);

    /* Create the session cipher and encrypt the message */
    // session_cipher *cipher;
    // session_cipher_create(&cipher, store_context, &address, global_context);

    // ciphertext_message *encrypted_message;
    // session_cipher_encrypt(cipher, message, message_len, &encrypted_message);

    /* Get the serialized content and deliver it */
    // signal_buffer *serialized = ciphertext_message_get_serialized(encrypted_message);

    // deliver(signal_buffer_data(serialized), signal_buffer_len(serialized));

    /* Cleanup */
    // SIGNAL_UNREF(encrypted_message);
    // session_cipher_free(cipher);
    session_builder_free(builder);
    signal_protocol_store_context_destroy(store_context);
    return 0;
}