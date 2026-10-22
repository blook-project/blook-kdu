-- blook-kdu: self-contained Windows kernel driver exploitation toolkit.
--
-- Targets
--   kdu_base            static  core utilities (win32, services, PE, traces)
--   kdu_exploit_common  static  shared exploit plumbing (base class, access)
--   kdu_exploit_<n>     static  one target per exploit (independent translation
--                               units, own embedded driver data)
--   kdu_exploits        static  registry that references every exploit
--   kdu_loader          static  manual mapper (stage-1 bootstrap + PE staging)
--   kdu_ipc             static  blook-kchannel adapter (+ kchannel source drop)
--   kdu_payload         binary  kernel payload driver (manual-mapped, WDK)
--   kdu_sdk             static  public SDK implementation (include/blook/kdu)
--   kdu                 binary  the CLI
--   kdu_tests                  host unit tests (doctest)
--   kdu_exploit_test_<n>       per-exploit unit tests (one binary per exploit)
--
-- Options
--   --kchannel_dir=<dir>   blook-kchannel checkout (required for payload/IPC)
--   --build_tests=y|n      build host unit tests (default: y)
--
-- WDK: pass the Windows Kits root with xmake's built-in option,
--   xmake f -y --wdk="C:/path/to/Kits/10"
-- (the WDK NuGet package layout, e.g. %RUNNER_TEMP%/wdk/c, works too).
--
-- blook-kchannel is consumed as a source drop (upstream docs/integration.md):
--   user   : src/user/*.cpp   + src/common/*.cpp
--   kernel : src/kernel/*.cpp + src/common/*.cpp
-- CI pins KCHANNEL_COMMIT and fails if the checkout is missing; a local build
-- without it still works for the exploit unit tests (payload/IPC are skipped).

add_rules("mode.debug", "mode.release")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
set_encodings("utf-8")
set_warnings("more")
set_languages("cxx20")
set_version("1.1.0")  -- keep in sync with version.txt / include/blook/kdu/version.h

option("kchannel_dir")
    set_showmenu(true)
    set_description("blook-kchannel checkout (payload + IPC source drop)")
option_end()
option("build_tests")
    set_showmenu(true)
    set_default(true)
    set_description("Build host unit tests")
option_end()
option("drvlite_dir")
    set_showmenu(true)
    set_description("blook-drv-lite checkout (payload backend source drop)")
option_end()

local kchannel_dir = get_config("kchannel_dir")
if not kchannel_dir then
    local local_kchannel = path.join(os.projectdir(), "..", "blook-kchannel")
    if os.isfile(path.join(local_kchannel, "include", "blook", "kchannel.h")) then
        kchannel_dir = local_kchannel
    end
end
local drvlite_dir = get_config("drvlite_dir")
if not drvlite_dir or drvlite_dir == "" then
    local local_drvlite = path.join(os.projectdir(), "..", "blook-drv-lite")
    if os.isfile(path.join(local_drvlite, "include", "blook", "drvlite",
                           "sdk.h")) then
        drvlite_dir = local_drvlite
    end
end
print("kdu: drvlite_dir=" .. tostring(drvlite_dir))
local has_drvlite = drvlite_dir ~= nil and
                    os.isfile(path.join(drvlite_dir, "include", "blook",
                                        "drvlite", "sdk.h")) and
                    #os.files(path.join(drvlite_dir, "src", "driver",
                                       "*.cpp")) > 0
local has_kchannel = kchannel_dir ~= nil and
                     os.isfile(path.join(kchannel_dir, "include", "blook",
                                         "kchannel.h"))
local has_kchannel_user = has_kchannel and
                          #os.files(path.join(kchannel_dir, "src", "user",
                                             "*.cpp")) > 0
local has_kchannel_kernel = has_kchannel and
                            #os.files(path.join(kchannel_dir, "src", "kernel",
                                                "*.cpp")) > 0
local has_ipc = has_kchannel_user and has_drvlite
local build_payload = has_kchannel_kernel and has_drvlite and
                      is_plat("windows")
local build_tests = get_config("build_tests") ~= false

if not has_kchannel then
    print("warning: blook-kchannel sources not found; the payload, IPC, SDK " ..
          "and CLI targets are skipped (pass --kchannel_dir=<checkout>)")
elseif not has_drvlite then
    print("warning: blook-drv-lite sources not found; the payload backend is " ..
          "skipped (pass --drvlite_dir=<checkout>)")
elseif not has_kchannel_user or not has_kchannel_kernel then
    print("warning: blook-kchannel checkout is incomplete; payload/IPC " ..
          "targets are skipped")
end

add_requires("fmt", "spdlog", "nlohmann_json")
add_requires("cli11")
add_requires("doctest")

-- Builder calls below apply to the current target in this file.
local function kdu_user_defaults()
    set_encodings("utf-8")
    set_languages("cxx20")
    add_defines("UNICODE", "NOMINMAX", "WIN32_LEAN_AND_MEAN",
                "_CRT_SECURE_NO_WARNINGS")
    add_includedirs("include", "src", {public = true})
    add_syslinks("advapi32", "user32", "shell32", "psapi", "ntdll", "version",
                 "ole32", "crypt32", "wintrust", "bcrypt", "wevtapi")
    add_defines('DRVLITE_VERSION="1.0.1"')
    if has_kchannel_user then
        add_includedirs(path.join(kchannel_dir, "include"))
        add_defines("KDU_HAS_KCHANNEL=1")
    end
end

-- ---------------------------------------------------------------------------
-- MASM rule (drv-lite's syscall trampoline is written in .asm)
-- ---------------------------------------------------------------------------
rule("kdu.masm")
    set_extensions(".asm")
    on_build_file(function (target, sourcefile, opt)
        import("core.project.depend")
        import("core.tool.toolchain")
        local tc = toolchain.load("msvc", {plat = target:plat(), arch = target:arch()})
        local compiler = tc:tool("as")
        local objectfile = target:objectfile(sourcefile)
        table.insert(target:objectfiles(), objectfile)
        depend.on_changed(function ()
            os.mkdir(path.directory(objectfile))
            os.vrunv(compiler,
                     {"/nologo", "/c", "/Fo" .. objectfile, sourcefile},
                     {envs = tc:runenvs()})
        end, {dependfile = target:dependfile(objectfile), files = {sourcefile},
              changed = target:is_rebuilt()})
    end)
rule_end()

-- ---------------------------------------------------------------------------
-- core utilities
-- ---------------------------------------------------------------------------
target("kdu_base")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/core/*.cpp")
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- shared exploit plumbing
-- ---------------------------------------------------------------------------
target("kdu_exploit_common")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/exploits/common/*.cpp")
    add_deps("kdu_base")
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- exploits: one static library per exploit directory
-- ---------------------------------------------------------------------------
local exploit_names = {}
for _, dir in ipairs(os.dirs("src/exploits/*")) do
    local name = path.basename(dir)
    if name ~= "common" and name ~= "data" and
       #os.files(path.join(dir, "*.cpp")) > 0 then
        table.insert(exploit_names, name)
    end
end
table.sort(exploit_names)

for _, name in ipairs(exploit_names) do
    target("kdu_exploit_" .. name)
        set_kind("static")
        kdu_user_defaults()
        add_files("src/exploits/" .. name .. "/*.cpp")
        add_deps("kdu_base", "kdu_exploit_common")
        add_packages("fmt", "spdlog")
end

target("kdu_exploits")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/exploits/registry.cpp")
    add_deps("kdu_base", "kdu_exploit_common")
    for _, name in ipairs(exploit_names) do
        add_deps("kdu_exploit_" .. name)
    end
    add_packages("fmt", "spdlog")
    -- Keep the generated registry in sync with the exploit directories at build
    -- time (adding src/exploits/<name>/ is enough to register an exploit).
    before_build(function (target)
        local script = path.join(os.projectdir(), "scripts",
                                 "gen-exploit-registry.ps1")
        os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                script .. '"')
    end)

-- ---------------------------------------------------------------------------
-- kernel stage image (tiny WDK driver mapped into a victim driver's .text)
-- ---------------------------------------------------------------------------
if build_payload then
    target("kdu_stage")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("src/loader/stage/*.cpp")
        add_includedirs("src", "src/loader")
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "NTDDI_VERSION=0x0A00000C")
        add_syslinks("ntoskrnl", "wdmsec")
        add_cxflags("/GS-", "/GR-", "/W4", {force = true})
        add_ldflags("/ENTRY:kdu_stage_entry", "/MERGE:.rdata=.text",
                    "/MERGE:.pdata=.text", "/MERGE:.kparam=.text",
                    "/SECTION:.text,ER", {force = true})
        after_build(function (target)
            local script = path.join(os.projectdir(), "scripts",
                                     "gen-payload-blob.ps1")
            local output = path.join(os.projectdir(), "build", "generated",
                                     "stage_blob.h")
            os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                    script .. '" -InputFile "' .. target:targetfile() ..
                    '" -OutputFile "' .. output ..
                    '" -Symbol kdu_stage_image')
        end)
end

-- ---------------------------------------------------------------------------
-- manual mapper
-- ---------------------------------------------------------------------------
target("kdu_loader")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/loader/*.cpp")
    add_includedirs(path.join(os.projectdir(), "build", "generated"))
    add_deps("kdu_base")
    if build_payload then
        add_deps("kdu_stage")
    end
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- IPC (blook-kchannel adapter) + kernel payload
-- ---------------------------------------------------------------------------
if has_ipc then
    target("kdu_ipc")
        set_kind("static")
        kdu_user_defaults()
        add_files("src/ipc/*.cpp")
        add_deps("kdu_base")
        add_packages("fmt", "spdlog")
        add_includedirs(path.join(kchannel_dir, "src"),
                        path.join(drvlite_dir, "include"),
                        path.join(drvlite_dir, "src"),
                        path.join(drvlite_dir, "src", "core"),
                        path.join(os.projectdir(), "build", "generated"))
        add_files(path.join(kchannel_dir, "src", "user", "*.cpp"),
                  path.join(kchannel_dir, "src", "common", "*.cpp"),
                  path.join(drvlite_dir, "src", "sdk", "*.cpp"),
                  path.join(drvlite_dir, "src", "core", "*.cpp"))
        if build_payload then
            -- payload blob header is generated by the payload after_build step
            add_deps("kdu_payload")
        end
end

if build_payload then
    target("kdu_payload")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm", "kdu.masm")
        set_values("wdk.env.winver", "win10_vb")
        set_languages("cxx17")
        set_exceptions("no-cxx")
        add_files(path.join(drvlite_dir, "src", "driver", "*.cpp"),
                  path.join(drvlite_dir, "src", "driver", "*", "*.cpp"),
                  path.join(drvlite_dir, "src", "driver", "*", "*.asm"),
                  path.join(drvlite_dir, "src", "core", "*.cpp"))
        add_files(path.join(kchannel_dir, "src", "kernel", "*.cpp"),
                  path.join(kchannel_dir, "src", "common", "*.cpp"))
        add_includedirs(path.join(drvlite_dir, "include"),
                        path.join(drvlite_dir, "src"),
                        path.join(drvlite_dir, "src", "core"),
                        path.join(drvlite_dir, "src", "driver"),
                        path.join(kchannel_dir, "include"),
                        path.join(kchannel_dir, "src"))
        add_defines("NOMINMAX", "POOL_NX_OPTIN=1", "KDU_HAS_KCHANNEL=1",
                    "DRVLITE_VERSION=\"1.0.1\"", "NTDDI_VERSION=0x0A00000C")
        add_cxxflags("/kernel", "/W4", "/GR-", "/EHs-c-",
                     "/Zc:threadSafeInit-", "/GS-", "/utf-8", {force = true})
        add_syslinks("ntoskrnl", "hal", "wdmsec")
        add_ldflags("/INTEGRITYCHECK", "/ENTRY:DriverEntry", {force = true})
        set_encodings("utf8")
        -- Turn the linked .sys into a C array header so the CLI carries the
        -- payload inside its own image (single self-contained exe). The image
        -- is also test-signed locally so the service-load path can start it on
        -- a test-signing guest; CI does not need a signature.
        after_build(function (target)
            -- Sign first: the embedded blob must carry the signature because
            -- the service-load path writes it to disk and starts it.
            local ci = os.getenv("CI") or os.getenv("GITHUB_ACTIONS")
            local signer = path.join(os.projectdir(), "signer", "spcsign",
                                     "spcsign.exe")
            if not ci and os.isfile(signer) then
                os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                        path.join(os.projectdir(), "scripts", "sign.ps1") ..
                        '" -Files "' .. target:targetfile() .. '"')
            end
            local blob = path.join(os.projectdir(), "scripts",
                                   "gen-payload-blob.ps1")
            local output = path.join(os.projectdir(), "build", "generated",
                                     "payload_blob.h")
            os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                    blob .. '" -InputFile "' .. target:targetfile() ..
                    '" -OutputFile "' .. output ..
                    '" -Symbol kdu_payload_image')
        end)
end

-- ---------------------------------------------------------------------------
-- e2e assets (guest test driver + marker process)
-- ---------------------------------------------------------------------------
if build_payload then
    target("kdu_guest_test_driver")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("tests/guest/*.c")
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "NTDDI_VERSION=0x0A00000C")
        add_cxflags("/W4", {force = true})
end

-- CI-only: minimal signed driver + client used by the kernel-load-smoke job.
if is_plat("windows") then
    target("kdu_ci_smoke_driver")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("tests/ci/kernel_smoke_driver.c")
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "NTDDI_VERSION=0x0A00000C")
        add_cxflags("/W4", {force = true})
        add_syslinks("ntoskrnl", "wdmsec")
        add_ldflags("/ENTRY:DriverEntry", {force = true})

    target("kdu_ci_smoke_client")
        set_kind("binary")
        kdu_user_defaults()
        add_files("tests/ci/kernel_smoke_client.cpp")
end

if has_ipc then
    target("kdu_api_example")
        set_kind("binary")
        kdu_user_defaults()
        add_files("examples/api_example.cpp")
        add_deps("kdu_sdk")
end

target("kdu_e2e_helper")
    set_kind("binary")
    kdu_user_defaults()
    add_files("tests/e2e/helper.cpp")
    add_deps("kdu_base")
-- ---------------------------------------------------------------------------
-- SDK + CLI (require the IPC adapter, i.e. real kchannel sources)
-- ---------------------------------------------------------------------------
if has_ipc then
    target("kdu_sdk")
        set_kind("static")
        kdu_user_defaults()
        add_files("src/sdk/*.cpp")
        add_deps("kdu_base", "kdu_exploits", "kdu_loader", "kdu_ipc")
        add_packages("fmt", "spdlog")

    target("kdu")
        set_kind("binary")
        kdu_user_defaults()
        add_files("src/cli/*.cpp", "src/cli/commands/*.cpp")
        -- embedded vulnerable drivers (signed RCDATA resources; the table is
        -- generated by scripts/prepare-assets.ps1, which scripts/build.ps1 and
        -- CI run before configuring)
        add_files("src/assets.rc")
        add_deps("kdu_sdk")
        add_packages("cli11", "fmt", "spdlog", "nlohmann_json")
        -- Regenerate the signed embedded-driver table before the RC compiles.
        -- This must happen at build (not configure) time: `xmake f -c` cleans
        -- build/ after the project script ran.
        before_build(function (target)
            local script = path.join(os.projectdir(), "scripts",
                                     "prepare-assets.ps1")
            os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                    script .. '"')
        end)
end

-- ---------------------------------------------------------------------------
-- tests
-- ---------------------------------------------------------------------------
if build_tests then
    if has_ipc then
        target("kdu_tests")
            set_kind("binary")
            kdu_user_defaults()
            add_files("tests/unit/main.cpp", "tests/unit/core/*.cpp")
            add_includedirs("tests/unit")
            add_deps("kdu_sdk")
            add_packages("doctest", "fmt", "spdlog")
    end

    -- Per-exploit test binaries are independent of the SDK/IPC; CI runs each
    -- of them as its own job.
    for _, name in ipairs(exploit_names) do
        target("kdu_exploit_test_" .. name)
            set_kind("binary")
            kdu_user_defaults()
            add_files("tests/unit/exploits/main.cpp")
            add_files("tests/unit/exploits/" .. name .. "_test.cpp")
            add_includedirs("tests/unit")
            add_deps("kdu_exploit_" .. name, "kdu_exploit_common", "kdu_base")
            add_packages("doctest", "fmt", "spdlog")
    end
end
























