/**
 * Author: Jozef Makiš
 * Logon: xmakis00
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <regex>
/* OpenSSL headers */
#include  "openssl/bio.h"
#include  "openssl/ssl.h"
#include  "openssl/err.h"

using namespace std;

#define BUFFER_SIZE 1024

// retazec servera
string server;
bool server_b = false;
// retazec s nazom vystupneho suboru
string out_dir;
bool outdir_b = false;
// autentifikacny subor
string auth_file;
bool auth_file_b = false;
// subor s certifikatom
string cert_file;
bool cert_file_b = false;
// adresar s certifikatom
string cert_dir;
bool cert_addr_b = false;
// port
string port;
bool port_b = false;

// nove spravy
bool new_msgs = false;
// -T bol zadany
bool encrypred_T = false;
// -S bol zadany
bool non_encrypted_S = false;
// -d delete messages
bool delete_msgs = false;
// premenna pre peskocenie uz spracovaneho parametru
bool next_skip = false;
// data from auth file
string user;
string pass;
// Vytvorenie bio objektu.
BIO *bio;
// pocet zamzanych sprav
int deleted_count;

char buf[BUFFER_SIZE];

/**
 *
 * @param response retazec odpovede
 * @param type cast programu, ktora sa kontroluje
 */
void check_connect_response(string response, const string &type) {
    response = response.substr(0, 3);
    for_each(response.begin(), response.end(), [](char &c) {
        c = ::toupper(c);
    });
    if (!(response == "+OK") and type == "connect") {
        cerr << "ERR odpoved servera !" << endl;
        exit(1);
    } else if (!(response == "+OK") and type == "TLS") {
        cerr << "ERR nepodarilo sa prejst na TLS !" << endl;
        exit(1);
    } else if (!(response == "+OK") and type == "QUIT") {
        cerr << "ERR nepodarilo sa uspesne ukoncit spojenie !" << endl;
        exit(1);
    } else if (!(response == "+OK") and type == "USER") {
        cerr << "ERR nespravne meno usera !" << endl;
        exit(1);
    } else if (!(response == "+OK") and type == "PASS") {
        cerr << "ERR nespravne heslo !" << endl;
        exit(1);
    } else if (!(response == "+OK") and type == "STAT") {
        cerr << "ERR prikaz STAT zlyhal !" << endl;
        exit(1);
    }
}

/**
 * Funkcia na spracovanie argumentov prikazovej riadky.
 * @param argc Pocet argumentov.
 * @param argv Pole argumentov.
 * @return 1 ak nastala chyba, inak 0.
 */
int parse_args(int argc, char *argv[]) {
    if (argc == 0 or argc == 1) {
        cerr << "Chybaju argumenty!" << endl;
        return 1;
    }

    for (int i = 1; i < argc; i++) {

        if (next_skip) {
            next_skip = false;
            continue;
        }

        if (strcmp(argv[i], "-a") == 0) {
            if (argv[i + 1] == nullptr) {
                cerr << "Chyba argument" << endl;
                exit(1);
            }
            auth_file = argv[i + 1];
            auth_file_b = true;
            next_skip = true;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (argv[i + 1] == nullptr) {
                cerr << "Chyba argument" << endl;
                exit(1);
            }
            out_dir = argv[i + 1];
            outdir_b = true;
            next_skip = true;
        } else if (strcmp(argv[i], "-p") == 0) {
            if (argv[i + 1] == nullptr) {
                cerr << "Chyba argument" << endl;
                exit(1);
            }
            port = argv[i + 1];
            port_b = true;
            next_skip = true;
        } else if (strcmp(argv[i], "-n") == 0) {
            new_msgs = true;
        } else if (strcmp(argv[i], "-d") == 0) {
            delete_msgs = true;
        } else if (strcmp(argv[i], "-T") == 0) {
            encrypred_T = true;
            port = "995";
            if (non_encrypted_S) {
                cerr << "Nespravna kombinacia argumentov T/S" << endl;
                return 1;
            }
        } else if (strcmp(argv[i], "-S") == 0) {
            non_encrypted_S = true;
            port = "110";
            if (encrypred_T) {
                cerr << "Nespravna kombinacia argumentov T/S" << endl;
                return 1;
            }
        } else if (strcmp(argv[i], "-c") == 0) {
            if (argv[i + 1] == nullptr) {
                cerr << "Chyba argument" << endl;
                exit(1);
            }
            cert_file = argv[i + 1];
            cert_file_b = true;
            next_skip = true;
        } else if (strcmp(argv[i], "-C") == 0) {
            if (argv[i + 1] == nullptr) {
                cerr << "Chyba argument" << endl;
                exit(1);
            }
            cert_dir = argv[i + 1];
            cert_addr_b = true;
            next_skip = true;
        } else {
            if (server_b) {
                cerr << "Neexistujuci argument !" << endl;
                return 1;
            }

            server = argv[i];
            server_b = true;
        }

    }

    /**
     * Osestrenie chybnych kombinacii parametrov.
     */
    if (!server_b) {
        cerr << "Chyba server !" << endl;
        return 1;
    } else if (!auth_file_b) {
        cerr << "Nebola zadana cesta k konfiguracnemu suboru !" << endl;
        return 1;
    } else if (!outdir_b) {
        cerr << "Nebol zadany vystupny adresar !" << endl;
        return 1;
    } else if (!encrypred_T and !non_encrypted_S) {
        if (cert_addr_b or cert_file_b) {
            cerr << "Certifikacne subory musia byt s parametrom na komunikaciu pomocou SSL/TLS !" << endl;
            return 1;
        }
    }

    return 0;
}

/**
 * Funkcia ziska potrebne udaje zo konfiguracneho suboru ako je meno a heslo.
 * @return vrati 1 v pripade chyby, inak 0
 */
int read_auth_file() {
    ifstream auth_f(auth_file);

    if (auth_f.is_open()) {
        string file_line;
        regex re_user("^username = [a-zA-Z0-9._]+$");
        regex re_pass("^password = [a-zA-Z0-9._]+$");
        smatch base_result;
        while (getline(auth_f, file_line)) {
            if (regex_match(file_line, base_result, re_user)) {
                user = file_line.substr(11);
            } else if (regex_match(file_line, base_result, re_pass)) {
                pass = file_line.substr(11);
            } else {
                cerr << "Nespravny tvar konfiguracneho suboru !" << endl;
                exit(1);
            }
        }
        auth_f.close();
    } else {
        cerr << "Nepodarilo sa otvorit konfiguracny subor !" << endl;
        exit(1);
    }

    return 0;
}

/**
 * Funkcia ktora pomocou parametru zapise spravu na socket.
 * @param message
 */
/**
* Zapis na socket je prevzany zo zdroja:
* https://www.openssl.org/docs/man1.0.2/man3/BIO_write.html
* https://developer.ibm.com/tutorials/l-openssl/ By Kenneth Ballard, Published July 22, 2004.
* Dna 2.11.2021 11:10.
*/
void write_command(const string &message) {

    if (BIO_write(bio, message.c_str(), (int) message.length()) <= 0) {
        if (!BIO_should_retry(bio)) {
            cerr << "Spojenie sa nepodarilo obnovit !" << endl;
            exit(1);
        }

        cerr << "Prikaz zlyhal !" << endl;
        exit(1);
    }
}

/**
 * Funkcia precita spravu zo socketu.
 * @return Ziskana sprava v urcitom mnozstve.
 */
/**
* Citanie z socketu je prevzane zo zdroja:
* https://www.openssl.org/docs/man1.0.2/man3/BIO_read.html
* https://developer.ibm.com/tutorials/l-openssl/ By Kenneth Ballard, Published July 22, 2004.
* Dna 1.11.2021 10:02.
*/
string read_connection() {
    // vycistenie buffera, pri neprecisteni zostava bordel
    memset(buf, 0, BUFFER_SIZE);
    int x = BIO_read(bio, buf, BUFFER_SIZE);

    if (x == 0) {
        cerr << "Spojenie bolo uzatvorene !" << endl;
        exit(1);
    } else if (x < 0) {
        if (!BIO_should_retry(bio)) {
            cerr << "Spojenie sa nepodarilo obnovit !" << endl;
            exit(1);
        }

        cerr << "Spojenie je neuspesne !" << endl;
        exit(1);
    }
    return buf;
}

/**
 * Funkcia sa pripoji na server a overi pripojenie.
 */
/**
* Nezabezpecene pripojenie je cerpane zo zdroja:
* https://developer.ibm.com/tutorials/l-openssl/ By Kenneth Ballard, Published July 22, 2004.
* Dna 1.11.2021 17:33
*/
void connect_to_server() {
    string response;

    bio = BIO_new_connect((server + ":" + port).c_str());

    if (bio == nullptr) {
        cerr << "Nepodarilo sa vytvorit BIO object." << endl;
        exit(1);
    }

    if (BIO_do_connect(bio) <= 0) {
        cerr << "Nepodarilo sa pripojit k serveru." << endl;
        exit(1);
    }
    // overenie si spravnost pripojenia zo socketu, pomocou spravy +OK (podpora lowercase zapisu)
    response = read_connection();
    check_connect_response(response, "connect");
}

/**
 * Funkcia sa pripoji pomocou SSL pripoji na server
 */
/**
 * Pripojenie pomocou SSL prevzane zo zdrojov:
 * https://www.openssl.org/docs/man1.0.2/man3/BIO_new_ssl_connect.html
 * https://developer.ibm.com/tutorials/l-openssl/ By Kenneth Ballard, Published July 22, 2004.
 * https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_load_verify_locations.html
 * Dna 1.11.2021 19:45
 */
void secured_connect_to_server() {
    string response;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl;

    if (ctx == nullptr) {
        cerr << "Nastavenie pripojenia zlyhalo !" << endl;
        exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, cert_file.c_str(), nullptr) and cert_file_b) {
        cerr << "Nepodaril sa nacitat subor s certifikatom !" << endl;
        exit(1);
    } else if (!SSL_CTX_load_verify_locations(ctx, nullptr, cert_dir.c_str()) and cert_addr_b) {
        cerr << "Nepodarilo sa najst cestu k certifikatom !" << endl;
        exit(1);
    } else if (!cert_file_b and !cert_addr_b) {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    bio = BIO_new_ssl_connect(ctx);

    if (bio == nullptr) {
        cerr << "Nepodarilo sa nadviazat ssl spojenie !" << endl;
        exit(1);
    }

    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
        cerr << "Nepodarilo sa ziskat ssl pointer !" << endl;
        exit(1);
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, (server + ":" + port).c_str());

    if (BIO_do_connect(bio) <= 0) {
        cerr << "Nepodarilo sa nadviazat zabezpecene spojenie so serverom !" << endl;
        exit(1);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        cerr << "Certifikat nie je pouzitelny !" << endl;
        exit(1);
    }
    // overenie si spravnost pripojenia zo socketu, pomocou spravy +OK (podpora lowercase zapisu)
    response = read_connection();
    check_connect_response(response, "connect");
    SSL_CTX_free(ctx);
}

/**
 * Funkcia sa pripoji na server pomocou nesifrovaneho spojenia na porte 110,
 * nasledne pomocou prikazu STLS prejde na sifrovanu variatu protokolu.
 */
/**
 * Cerpane z
 * https://linux.die.net/man/3/bio_get_ssl
 * https://stackoverflow.com/questions/49132242/openssl-promote-insecure-bio-to-secure-one
 * Autor otazky: eko, Mar, 6 2018 at 13:41
 * Autor odpovede: Martin Prikryl, Mar 6 2018 at 13:54
 * Prevzane dna 1.11. 22:44
 */
void upgraded_connection_to_server() {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl;
    string response;

    if (ctx == nullptr) {
        cerr << "Nastavenie pripojenia zlyhalo !" << endl;
        exit(1);
    }

    bio = BIO_new_connect((server + ":" + port).c_str());

    if (bio == nullptr) {
        cerr << "Nepodarilo sa pripojit na server !" << endl;
        exit(1);
    }

    response = read_connection();
    check_connect_response(response, "connect");

    write_command("STLS\r\n");
    response = read_connection();
    check_connect_response(response, "TLS");

    BIO *updateSSL = nullptr;

    if (!SSL_CTX_load_verify_locations(ctx, cert_file.c_str(), nullptr) and cert_file_b) {
        cerr << "Nepodaril sa nacitat subor s certifikatom !" << endl;
        exit(1);
    } else if (!SSL_CTX_load_verify_locations(ctx, nullptr, cert_dir.c_str()) and cert_addr_b) {
        cerr << "Nepodarilo sa najst cestu k certifikatom !" << endl;
        exit(1);
    } else if (!cert_file_b and !cert_addr_b) {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    updateSSL = BIO_new_ssl(ctx, 1);
    if (updateSSL == nullptr) {
        cerr << "Nepodarilo sa vylepsit nezabezpecene spojenie !" << endl;
        exit(1);
    }

    bio = BIO_push(updateSSL, bio);
    if (bio == nullptr) {
        cerr << "Nepodarilo sa vylepsit nezabezpecene spojenie !" << endl;
        exit(1);
    }

    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
        cerr << "Nepodarilo sa ziskat ssl pointer !" << endl;
        exit(1);
    }

    if (BIO_do_connect(bio) <= 0) {
        cerr << "Nepodarilo sa nadviazat zabezpecene spojenie so serverom !" << endl;
        exit(1);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        cerr << "Certifikat nie je pouzitelny !" << endl;
        exit(1);
    }

    SSL_CTX_free(ctx);
}

/**
 * Funkcia prihlasi uzivatela za pomoci jeho mena a hesla zo suboru.
 */
void log_in() {
    string response;

    write_command("USER " + user + "\r\n");
    response = read_connection();
    check_connect_response(response, "USER");

    write_command("PASS " + pass + "\r\n");
    response = read_connection();
    check_connect_response(response, "PASS");
}

/**
 *
 * @param filename Nazov a cesta k soboru.
 * @return true ak subor existuje, inak false
 */
bool file_exists(const string &filename) {
    ifstream ifile;
    ifile.open(filename);
    if (!ifile) {
        return false;
    }
    ifile.close();
    return true;
}

/**
 * Funkcia korektne ukonci spojenie so serverom.
 */
void end_connection() {
    string response;
    write_command("QUIT\r\n");
    response = read_connection();
    check_connect_response(response, "QUIT");
}

/**
 * Funkcia postupne stahuje e-maily zo servera. Z odpovede odstranuje byte buffering a odpoved servera.
 * V pripade ze subor existuje tak sa vymaze a nahradi s rovnakym obsahom e-mailu.
 * Pri parametri -n sa zisti message-id stahovaneho suboru a nasledne sa porovna
 * so suborom s rovnakym nazvom. Nazov ulozenej spravy udava predmet e-mailu.
 */
void download_mails() {
    string response;
    string state;
    smatch pieces_match;
    ssub_match sub_match;
    string piece;

    int mail_count = -1;
    int new_mail_count = 0;

    write_command("STAT\r\n");
    response = read_connection();

    // odstranenie /r/n z odpovede
    const std::string responses[] = {response};

    const std::regex pieces_regex(R"((\+OK) ([0-9]+) .*\r\n)");

    for (const auto &aresponse: responses) {
        if (std::regex_match(aresponse, pieces_match, pieces_regex)) {
            for (size_t i = 0; i < pieces_match.size(); ++i) {
                sub_match = pieces_match[i];
                // na pozicii 1 je odpoved -ERR alebo +OK
                if (i == 1) {
                    if (!(sub_match == "+OK")) {
                        cerr << "ERR pri STAT nepodarilo sa ziskat stav mailu !" << endl;
                        exit(1);
                    }
                } else if (i == 2) {
                    // druha pozicia s poctom mailov
                    mail_count = stoi(sub_match);
                }
            }
        }
    }

    if (mail_count == -1) {
        cerr << "Chyba pri ziskani poctu mailov." << endl;
        exit(1);
    }

    for (int i = 1; i <= mail_count; i++) {
        write_command("RETR " + to_string(i) + "\r\n");
        string msg;
        // po urcitych castiach vo velkosti buffera sa nacita sprava, ktora sa konkatenuje ku celkovej
        // odpovedi pokial sa neojavi ukoncenie spravy /r/n./r/n
        smatch end;
        regex end_re(R"(\r\n\.\r\n)"); // message end
        while (!regex_search(msg, end, end_re)) {
            response = read_connection();
            msg += response;
        }
        // nahradenie byte-stuffingu
        regex dot_replace(R"((\r\n\.\.))");
        msg = regex_replace(msg, dot_replace, "\r\n.");
        msg.erase(msg.length() - 5); // odstrani /r/n./r/n
        regex re_user(R"((\+OK)(.*)(\r\n))"); // regex na odpoved
        smatch base_result;
        regex_search(msg, base_result, re_user); // hladanie hlavicky
        response = msg.substr(0, 3);
        // prevod podvede na velke pismena
        for_each(response.begin(), response.end(), [](char &c) {
            c = ::toupper(c);
        });
        if (!(response == "+OK")) {
            cerr << "ERR spracovanie spravy zlyhalo !" << endl;
            exit(1);
        }

        msg = regex_replace(msg, re_user, ""); // odstranenie odpovede pomocou regexu

        regex msg_id(R"((\r\n)([mM][eE][sS][sS][aA][gG][eE]\-[iI][dD]:)(.*)(\r\n))"); // regex na  message ID
        regex subject(R"((\r\n)([sS][uU][bB][jj][eE][cC][tT]:)(.*)(\r\n))"); // regex na  subject

        smatch match_id;
        smatch match_subject;
        // vyhladanie udajov ID a SUBJECT
        regex_search(msg, match_id, msg_id);
        regex_search(msg, match_subject, subject);

        string matched_subject = match_subject[0]; // premenna pre najduty predmet
        regex rnrn(R"((\r\n))"); // regularny vyraz pre zmazanie rnrn
        regex spaces(R"( )"); // regularny vyraz pre zmazanie rnrn
        matched_subject = regex_replace(matched_subject, rnrn, ""); // nahradenie rnrn prazdnym retazcom
        matched_subject = regex_replace(matched_subject, spaces, ""); // odstranenie medzier
        // ak subor je bez predmetu tak sa nastavi empty varianta. Substr odseklne subject cast.
        if (matched_subject.substr(8).empty()) {
            matched_subject = "empty_subject_" + to_string(i);
        } else {
            matched_subject = matched_subject.substr(8);
        }
        // retazec s nazvom suboru obsahujuci cisto predmet bez Subject:
        string filepath = out_dir + "/" + matched_subject;
        // zapis mailu do suboru
        ofstream mail_file;
        // ak subor existuje tak sa pokracuje v overeni, inak sa zapise sprava do subora a koniec
        if (file_exists(filepath) and !new_msgs) {
            // subor existuje a parameter -n nebol zadany, sprava sa stiahne
            mail_file.open(filepath, ios::trunc);
            mail_file << msg;
            mail_file.close();
        } else if (new_msgs) {
            // -n bol zadany, subor sa naticata do stringu porovna sa MESSAGE-ID, ak ten subor neni stiahnuty
            // tak sa stiahne a inkrementuje sa pocet novych stiahnutych sprav
            ifstream mail(filepath);
            stringstream buffer;
            buffer << mail.rdbuf();
            string mail_msg = buffer.str();
            smatch mail_msg_id;
            if (!(regex_search(mail_msg, mail_msg_id, msg_id))) {
                mail_file.open(filepath, ios::trunc);
                mail_file << msg;
                mail_file.close();
                new_mail_count++;
            }
        } else {
            // subor neexistuje, vytvori sa subor a sprava sa ulozi
            mail_file.open(filepath, ios::app);
            mail_file << msg;
            mail_file.close();
        }
    }
    // po stiahnuti sprav sa ukonci spojenie
    end_connection();

    if (!new_msgs) {
        cout << "Stiahnute " + to_string(mail_count) + " sprav." << endl;
    } else {
        cout << "Stiahnute novych " + to_string(new_mail_count) + " sprav." << endl;
    }
}

void delete_messages() {
    string response;
    smatch pieces_match;
    ssub_match sub_match;
    int mailcount = -1;

    write_command("STAT\r\n");
    response = read_connection();
    // spracovanie odpovede na STAT, nasledne ziskanie poctu mailov.
    const std::string responses[] = {response};
    const std::regex pieces_regex(R"((\+OK) ([0-9]+) .*\r\n)");

    for (const auto &aresponse: responses) {
        if (std::regex_match(aresponse, pieces_match, pieces_regex)) {
            for (size_t i = 0; i < pieces_match.size(); ++i) {
                sub_match = pieces_match[i];
                // na pozicii 1 je odpoved -ERR alebo +OK
                if (i == 1) {
                    if (!(sub_match == "+OK")) {
                        cerr << "ERR pri STAT nepodarilo sa ziskat stav mailu !" << endl;
                        exit(1);
                    }
                } else if (i == 2) {
                    // druha pozicia s poctom mailov
                    mailcount = stoi(sub_match);
                }
            }
        }
    }
    // nepodarilo sa zistit pocet mailov
    if (mailcount == -1) {
        cerr << "Chyba pri ziskani poctu mailov." << endl;
        exit(1);
    }
    // pomocou DELE vymaze postupe vsetky spravy a pre uplnost ukonci spojenie
    for (int i = 1; i <= mailcount; i++) {
        write_command("DELE " + to_string(i) + "\r\n");
        string resp = read_connection();
        deleted_count++;
    }

    cout << "Zmazanych " + to_string(deleted_count) + " sprav."<< endl;
    end_connection();
}

int main(int argc, char *argv[]) {
    port = "110"; // defaultna hodnota portu pre POP3
    // overenie si spravnost argumentov
    if (parse_args(argc, argv) == 1) {
        return 1;
    }

    read_auth_file(); // nacitanie udajov z auth suboru

    /* Initializing OpenSSL */
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Pripoji a nastavi komunikaciu podla parametrov.
    if (encrypred_T) {
        secured_connect_to_server();
    } else if (non_encrypted_S) {
        upgraded_connection_to_server();
    } else {
        connect_to_server();
    }
    // Pokusi sa prihlasit uzivatela na zaklade udajov z auth_file
    log_in();
    // stiahne vsetky dostupne maily, inak maze
    if (!delete_msgs) {
        download_mails();
    } else {
        delete_messages();
    };

    memset(buf, 0, BUFFER_SIZE);
    BIO_flush(bio);
    BIO_free_all(bio);

    return 0;
}