#include <iostream>
#include <filesystem>

#include <memory>
#include <string>
#include <fstream>

#include <tao/pegtl/contrib/uri.hpp>
#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/analyze.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace openssl
{
    using EnvelopePrivateKeyUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
    using EnvelopePrivateKeyContextUPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
    using BasicInputOutputUPtr = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;

    class KeyPair
    {

    public:
        KeyPair() = default;
        KeyPair(const std::string &pr_in, const std::string &pub_in) : _private(pr_in), _public(pub_in) {}

        /// @brief Parses a certificate from a string
        ///
        /// @param in
        /// @return true on success, false otherwise
        bool fromString(const std::string &pr_in, const std::string &pr_out)
        {
            _private = pr_in;
            _public = pr_out;

            return isValid();
        }

        /// @brief Creates a new private RSA key
        ///
        /// @return true on success, false otherwise
        // virtual bool generate() = 0;

        /// @brief Checks if the key is valid
        ///
        /// @return true if valid, false otherwise
        bool isValid() const
        {
            auto key = toOpenssl();
            return (key != nullptr);
        }

        /// @brief Returns the key as string
        ///
        /// @return the key
        const std::pair<std::string, std::string> toString() const { return std::make_pair(_private, _public); }

        /// @brief Returns the key as an openssl EVP_PKEY object
        ///
        /// @return the key
        virtual openssl::EnvelopePrivateKeyUPtr toOpenssl() const = 0;

        bool operator==(const KeyPair &rhs) const { return _private == rhs._private; };

    protected:
        std::string _private;
        std::string _public;
    };

    namespace
    {
        std::string readfile(const std::filesystem::path filename)
        {
            std::ifstream stream(filename, std::ios::in);

            if (stream.is_open())
            {
                return {};
            }

            std::stringstream buffer;
            buffer << stream.rdbuf();

            return buffer.str();
        }
    }

    class EcdsaKeyPair final : public KeyPair
    {

    public:
        EcdsaKeyPair()
        {
            // generate();
        }

        EcdsaKeyPair(const std::string &private_key, const std::string &public_key) : KeyPair(private_key, public_key)
        {
        }

        EcdsaKeyPair(const std::filesystem::path &private_key, const std::filesystem::path &public_key) : KeyPair(readfile(private_key), readfile(public_key))
        {
        }

        /// @brief Creates a new private RSA key
        ///
        /// @return true on success, false otherwise
        // bool generate() override
        // {
        //     OpenSSL_add_all_algorithms();
        //     ERR_load_crypto_strings();

        //     // Create an EVP key context
        //     openssl::EnvelopePrivateKeyContextUPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), ::EVP_PKEY_CTX_free);
        //     if (!ctx)
        //     {
        //         return false;
        //     }

        //     // Initialize the key generation context
        //     if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        //     {
        //         return false;
        //     }

        //     //  We're going to use the ANSI X9.62 Prime 256v1 curve
        //     if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) != 1)
        //     {
        //         return false;
        //     }

        //     // Generate the key pair
        //     EVP_PKEY *keyTemp = nullptr;
        //     if (EVP_PKEY_keygen(ctx.get(), &keyTemp) <= 0)
        //     {
        //         return false;
        //     }

        //     openssl::EnvelopePrivateKeyUPtr key(keyTemp, ::EVP_PKEY_free);

        //     // Create a memory BIO to store the private key
        //     openssl::BasicInputOutputUPtr memPrBio(BIO_new(BIO_s_mem()), BIO_free_all);
        //     openssl::BasicInputOutputUPtr memPbBio(BIO_new(BIO_s_mem()), BIO_free_all);
        //     if (!memPrBio && !memPbBio)
        //     {
        //         return false;
        //     }

        //     // Write the private key to the memory BIO
        //     if (!PEM_write_bio_PrivateKey(memPrBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr))
        //     {
        //         return false;
        //     }

        //     // Write the public key to the memory BIO
        //     if (!PEM_write_bio_PUBKEY(memPbBio.get(), key.get()))
        //     {
        //         return false;
        //     }

        //     // Read the private key from the memory BIO to a string
        //     BUF_MEM *memBuf;
        //     BIO_get_mem_ptr(memPrBio.get(), &memBuf);

        //     _private = std::string(memBuf->data, memBuf->length);

        //     BIO_get_mem_ptr(memPbBio.get(), &memBuf);

        //     _public = std::string(memBuf->data, memBuf->length);

        //     // Clean up OpenSSL
        //     EVP_cleanup();
        //     ERR_free_strings();

        //     return true;
        // }

        /// @brief Returns the key as an openssl EVP_PKEY object
        ///
        /// @return the key
        [[nodiscard]] openssl::EnvelopePrivateKeyUPtr toOpenssl() const override
        {
            // Create a memory BIO to read the private key from the string
            openssl::BasicInputOutputUPtr memBio(BIO_new_mem_buf(_private.c_str(), -1), BIO_free_all);
            if (!memBio)
            {
                return {nullptr, ::EVP_PKEY_free};
            }

            // Read the private key from the memory BIO
            EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(memBio.get(), nullptr, nullptr, nullptr);
            if (!ecKey)
            {
                return {nullptr, ::EVP_PKEY_free};
            }

            openssl::EnvelopePrivateKeyUPtr key(EVP_PKEY_new(), ::EVP_PKEY_free);
            EVP_PKEY_assign_EC_KEY(key.get(), ecKey);

            return key;
        }
    };

} // namespace openssl

namespace sshd
{
    struct HostKey
    {
        std::filesystem::path private_key{};
        std::filesystem::path public_key{};
    };

    struct sshd_config
    {
        std::vector<HostKey> host_keys{};
    };

} // namespace

namespace sshd::config
{
    using namespace TAO_PEGTL_NAMESPACE;

    // clang-format off
    struct comment : seq< one< '#' >, until< eolf > > {};
    struct sp : sor< space, comment > {};
    struct sps : star< sp > {};

    struct sep : pegtl::sor< pegtl::ascii::space, comment > {};
    struct seps : pegtl::star< sep > {};

    struct path : uri::path {};

    struct yes : TAO_PEGTL_STRING("yes") {};
    struct no : TAO_PEGTL_STRING("no") {};

    struct Boolean : sor < yes, no > {};

    struct Decimal : seq< range< '1', '9' >, star< digit > >  {};
    struct Integer : sor< Decimal > {};

    struct ident_first : ranges< 'a', 'z', 'A', 'Z' > {}; 
    struct ident_other : ranges< 'a', 'z', 'A', 'Z', '0', '9', '_' > {};
    struct ident : seq< ident_first, star< ident_other > > {};

    struct String : ident {};

    struct HostKey_key : TAO_PEGTL_STRING("HostKey") {};
    struct HostKey : seq < HostKey_key, seps, path> {};

    struct PermitRootLogin_key : TAO_PEGTL_STRING("PermitRootLogin") {};
    struct PermitRootLogin : seq < PermitRootLogin_key, seps, Boolean> {};

    struct PermitEmptyPasswords_key : TAO_PEGTL_STRING("PermitEmptyPasswords") {};
    struct PermitEmptyPasswords : seq < PermitEmptyPasswords_key, seps, Boolean> {};

    struct UsePAM_key : TAO_PEGTL_STRING("UsePAM") {};
    struct UsePAM : seq < UsePAM_key, seps, Boolean> {};

    struct Compression_key : TAO_PEGTL_STRING("Compression") {};
    struct Compression : seq < Compression_key, seps, Boolean> {};

    struct ClientAliveInterval_key : TAO_PEGTL_STRING("ClientAliveInterval") {};
    struct ClientAliveInterval : seq < ClientAliveInterval_key, seps, Integer> {};

    struct ClientAliveCountMax_key : TAO_PEGTL_STRING("ClientAliveCountMax") {};
    struct ClientAliveCountMax : seq < ClientAliveCountMax_key, seps, Integer> {};

    struct ChallengeResponseAuthentication_key : TAO_PEGTL_STRING("ChallengeResponseAuthentication") {};
    struct ChallengeResponseAuthentication : seq < ChallengeResponseAuthentication_key, seps, Boolean> {};

    struct Subsystem_key : TAO_PEGTL_STRING("Subsystem") {};
    struct Subsystem : seq < Subsystem_key, seps, String, seps, path> {};

    struct AuthorizedKeysFile_key : TAO_PEGTL_STRING("AuthorizedKeysFile") {};
    struct AuthorizedKeysFile : seq < AuthorizedKeysFile_key, seps, path> {};

    struct parameters : sor<
            HostKey,
            PermitRootLogin,
            AuthorizedKeysFile,
            PermitEmptyPasswords,
            ChallengeResponseAuthentication,
            UsePAM,
            Compression,
            ClientAliveInterval,
            ClientAliveCountMax,
            Subsystem> {};

    struct body : parameters {};

    struct grammar : must< sps, star<body, sps> , eof> {};

    template< typename Rule >
    struct action
    {};

    template<>
    struct action< HostKey >
    {
        template< typename ActionInput >
        static void apply( const ActionInput& in, sshd::sshd_config & config )
        {
            if( !in.empty() ) {
                std::stringstream ss( in.string() );

                std::string param, private_key_path, public_key_path;

                ss >> param >> private_key_path;

                public_key_path = private_key_path + std::string(".pub");

                config.host_keys.push_back(sshd::HostKey{
                    .private_key=private_key_path,
                    .public_key=public_key_path
                });
            }
        }
    };
}

int main(int argc, char** argv) {
    using namespace TAO_PEGTL_NAMESPACE;

    sshd::sshd_config sshdConfig;

    if( analyze< sshd::config::grammar >() != 0 ) {
        return 1;
    }

    for( int i = 1; i < argc; ++i ) {
        file_input in( argv[ i ] );
        try {
            parse< sshd::config::grammar, sshd::config::action >( in , sshdConfig );
        }
        catch( const parse_error& e ) {
            const auto& positions = e.positions();
            for(auto &p : positions) {
                std::cerr << e.what() << '\n'
                          << in.line_at( p ) << '\n'
                          << std::setw( int( p.column ) ) << '^' << '\n';
            }
        }
    }

    for(auto & key: sshdConfig.host_keys) 
    {
        std::cout << key.private_key << "\t" << key.public_key << std::endl;

        openssl::EcdsaKeyPair keyPair(key.private_key, key.public_key);
    }

    return 0;
}
