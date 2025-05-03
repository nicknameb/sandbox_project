#pragma once
#include <string>

class PEAnalyzer {
public:
    static bool scanImports(const std::string& filepath);
};