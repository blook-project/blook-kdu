-- blook-kdu package manifest (installed from release assets).
--
-- The canonical asset is blook-kdu-<version>-windows-x64.zip with bin/, include/
-- and lib/ directories. After a release, scripts/publish-registry.ps1 copies this
-- file (with the real asset sha256) into blook-project/blook-xmake-repo.
package("blook-kdu")
    set_homepage("https://github.com/blook-project/blook-kdu")
    set_description("Self-contained Windows kernel driver exploitation toolkit with manual mapping, kernel payload and SDK")
    set_license("MIT")
    set_kind("library", {headeronly = false})

    add_urls("https://github.com/blook-project/blook-kdu/releases/download/v$(version)/blook-kdu-$(version)-windows-x64.zip")
    -- add_versions() is written by scripts/publish-registry.ps1
    add_versions("0.1.0", "0000000000000000000000000000000000000000000000000000000000000000")

    on_install("windows|x64", function (package)
        os.cp("include", package:installdir())
        os.cp("bin", package:installdir())
        os.cp("lib", package:installdir())
        os.cp("xmake-package/xmake.lua", package:installdir("xmake-package"))
    end)

    on_test(function (package)
        assert(os.isfile(path.join(package:installdir(), "include/blook/kdu/kdu.h")))
    end)
package_end()
