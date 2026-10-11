#pragma once

#include <string>
#include <vector>
#include <random>

namespace namegen {

    inline std::string generate() {
        // Списки прилагательных и существительных
        static const std::vector<std::string> adjectives = {
            "Quick", "Clever", "Brave", "Silent",
            "Wise", "Kind", "Loud", "Bright",
            "Calm", "Quiet", "Bold", "Swift",
            "Gentle", "Happy", "Lucky", "Keen",
            "Agile", "Nimble", "Daring", "Proud",
            "Honest", "Alert", "Loyal", "Noble",
            "Patient", "Curious", "Friendly", "Playful",
            "Lively", "Cheerful", "Hardy", "Steady"
        };
        
        static const std::vector<std::string> nouns = {
            "Fox", "Wolf", "Raven", "Sheep",
            "Duck", "Owl", "Bear", "Cat",
            "Lynx", "Hare", "Deer", "Dog",
            "Badger", "Moose", "Elk", "Horse",
            "Panda", "Koala", "Tiger", "Lion",
            "Zebra", "Leopard", "Falcon", "Hawk",
            "Eagle", "Robin", "Crane", "Swan",
            "Finch", "Lark", "Seal", "Dolphin"
        };
    
        // Инициализация генератора случайных чисел
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<size_t> adjective_dist(0, adjectives.size() - 1);
        static std::uniform_int_distribution<size_t> noun_dist(0, nouns.size() - 1);
    
        // Генерация случайного имени
        return adjectives[adjective_dist(gen)] + " " + nouns[noun_dist(gen)];
    }
    
}
