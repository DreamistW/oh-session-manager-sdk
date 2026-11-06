#include "../src/sftp_delete_policy.h"
#include <cassert>
#include <iostream>

int main()
{
    using homoxterm::IsSafeSftpDeletePath;
    for (const std::string path : {"", "/", "relative/file", "/demo/../file", "/demo/./file",
        "//demo/file", "/demo//file", "/demo/file/", "/demo/a\\b", "/demo/a\nb"}) {
        assert(!IsSafeSftpDeletePath(path));
    }
    assert(!IsSafeSftpDeletePath(std::string("/demo/a\0b", 9)));
    assert(!IsSafeSftpDeletePath("/demo/" + std::string(256, 'a')));
    assert(IsSafeSftpDeletePath("/demo/files/report.txt"));
    assert(IsSafeSftpDeletePath("/demo/file with spaces.txt"));
    std::cout << "SFTP_DELETE_POLICY_PASS\n";
}
