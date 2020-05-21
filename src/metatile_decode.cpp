#include <iostream>
#include <fstream>
#include <filesystem>
#include <memory>
#include <array>

#include "metatile.h"
#include "render_config.h"

std::string save(std::unique_ptr<char[]> && buffer, int size);
std::string save_piece(const entry_item & item, std::ifstream & filestream);
std::string create_filename();
std::string exec(const char * cmd);

int main(int argc, const char * argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: metatile_decode [metatile_path]" << std::endl;
    }
    
    const char * file = argv[1];
    
    /*
     * В заголовке метаплитки сериализована структура meta_layout.
     * Её внутренний массив entry_item index[] равен размеру метаплитки METATILE x METATILE
     */
    auto length =
        sizeof(meta_layout) + (METATILE * METATILE * sizeof(entry_item));
    
    auto buffer = std::make_unique<char[]>(length);
    
    std::ifstream file_stream;
    
    try
    {
        file_stream.open(file, std::ifstream::binary);
        file_stream.read(buffer.get(), length);
        
        const auto meta = reinterpret_cast<meta_layout *>(buffer.get());
        const auto & magic = std::string(meta -> magic);
        
        if (magic.find(META_MAGIC) == std::string::npos)
        {
            // Первые 4 байта в заголовке должны быть META или METZ
            throw std::runtime_error("Metatile header corrupted");
        }
        
        for (int i = 0; i < meta -> count; i++)
        {
            const auto & item = meta -> index[i];
            const auto & filename = save_piece(item, file_stream);
            
            std::cout << filename << std::endl;
        }
    }
    catch(std::exception & exception)
    {
        std::cerr
            << exception.what()
            << std::endl;
    }
    
    if (file_stream.is_open()) {
        file_stream.close();
    }
}

std::string save_piece(const entry_item & entry, std::ifstream & filestream)
{
    // Смещение относительно начала файла
    filestream.seekg(entry.offset, std::ifstream::beg);

    auto buffer = std::make_unique<char[]>(entry.size);
    filestream.read(buffer.get(), entry.size);
    
    return save(std::move(buffer), entry.size);
}

std::string save(std::unique_ptr<char[]> && buffer, int size)
{
    std::string filename = create_filename();
    std::ofstream output(filename, std::ifstream::binary);

    output.write(buffer.get(), size);
    output.close();

    return filename;
}

std::string create_filename()
{
    std::stringstream stream;
    
    // Работает в macOS/Linux
    auto guid = exec("/usr/bin/uuidgen");
    
    const auto & iterator = std::remove(guid.begin(), guid.end(), '\n');
    guid.erase(iterator, guid.end());
              
    stream << guid << ".png";
    return stream.str();
}

std::string exec(const char * cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}
