#!/usr/bin/env python3
"""Generate the small Xcode project deterministically, without external generators."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
objects = {}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", action="store_true", help="fail if generated files are stale; do not write")
args = parser.parse_args()
stale_paths = []

def write_generated(path, content):
    if path.exists() and path.read_text() == content:
        return
    if args.check:
        stale_paths.append(path.relative_to(ROOT))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

def identifier(key):
    return hashlib.sha256(key.encode()).hexdigest()[:24].upper()

def add(key, value):
    identity = identifier(key)
    objects[identity] = value
    return identity

def quoted(value):
    return json.dumps(str(value))

def array(values):
    return "(" + ", ".join(values) + ",)" if values else "()"

source_builds, resource_builds, file_refs = [], [], []
for path in sorted((ROOT / "App").rglob("*.swift")):
    relative = str(path.relative_to(ROOT))
    ref = add(relative, f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {quoted(relative)}; sourceTree = SOURCE_ROOT;')
    file_refs.append(ref)
    source_builds.append(add("build:" + relative, f"isa = PBXBuildFile; fileRef = {ref};"))
for relative, kind in [("App/GPS-Bridging-Header.h", "sourcecode.c.h"),
                       ("Config/Info.plist", "text.plist.xml"),
                       ("App/Resources/PrivacyInfo.xcprivacy", "text.xml"),
                       ("Config/Signing.xcconfig", "text.xcconfig")]:
    ref = add(relative, f'isa = PBXFileReference; lastKnownFileType = {kind}; path = {quoted(relative)}; sourceTree = SOURCE_ROOT;')
    file_refs.append(ref)
    if relative.endswith(".xcprivacy"):
        resource_builds.append(add("build:" + relative, f"isa = PBXBuildFile; fileRef = {ref};"))
assets = ROOT / "App/Resources/Assets.xcassets"
if assets.exists():
    ref = add("assets", 'isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = App/Resources/Assets.xcassets; sourceTree = SOURCE_ROOT;')
    file_refs.append(ref)
    resource_builds.append(add("build:assets", f"isa = PBXBuildFile; fileRef = {ref};"))
product = add("product", 'isa = PBXFileReference; explicitFileType = wrapper.application; path = GPS.app; sourceTree = BUILT_PRODUCTS_DIR;')
products = add("products", f'isa = PBXGroup; children = {array([product])}; name = Products; sourceTree = "<group>";')
group = add("root-group", f'isa = PBXGroup; children = {array(file_refs + [products])}; sourceTree = "<group>";')
sources = add("sources", f"isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = {array(source_builds)}; runOnlyForDeploymentPostprocessing = 0;")
resources = add("resources", f"isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = {array(resource_builds)}; runOnlyForDeploymentPostprocessing = 0;")
signing_package = add("package:sidesign", 'isa = XCLocalSwiftPackageReference; relativePath = Vendor/SideSign;')
signing_product = add("product:sidesign", f'isa = XCSwiftPackageProductDependency; package = {signing_package}; productName = SideSign;')
signing_link = add("build:sidesign", f'isa = PBXBuildFile; productRef = {signing_product};')
frameworks = add("frameworks", f"isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = {array([signing_link])}; runOnlyForDeploymentPostprocessing = 0;")
script = 'set -eu\ncase "$PLATFORM_NAME" in iphoneos) native_platform=device ;; iphonesimulator) native_platform=simulator ;; *) echo "Unsupported platform" >&2; exit 1 ;; esac\n"$SRCROOT/Native/build.sh" "$native_platform"\n'
# Cargo tracks Rust sources, vendored dependencies, and toolchain changes. Keep
# asking Cargo, but declare its product and preserve unchanged archive timestamps.
native_outputs = array([quoted("$(SRCROOT)/Native/build/$(PLATFORM_NAME)/libgpsnative.a")])
native = add("native-build", f'isa = PBXShellScriptBuildPhase; alwaysOutOfDate = 1; buildActionMask = 2147483647; files = (); inputPaths = (); outputPaths = {native_outputs}; name = "Build native location transport"; runOnlyForDeploymentPostprocessing = 0; shellPath = /bin/sh; shellScript = {quoted(script)};')

def settings(values):
    return "{ " + " ".join(f"{key} = {quoted(value)};" for key, value in values.items()) + " }"

project_configs, target_configs = [], []
for name in ("Debug", "Release"):
    debug = name == "Debug"
    common = {
        "CLANG_ENABLE_MODULES": "YES", "CLANG_ENABLE_OBJC_ARC": "YES", "GCC_C_LANGUAGE_STANDARD": "gnu17",
        "IPHONEOS_DEPLOYMENT_TARGET": "17.4", "SDKROOT": "iphoneos", "SWIFT_VERSION": "6.0", "ARCHS": "arm64",
        "SWIFT_STRICT_CONCURRENCY": "complete", "DEBUG_INFORMATION_FORMAT": "dwarf" if debug else "dwarf-with-dsym",
        "SWIFT_OPTIMIZATION_LEVEL": "-Onone" if debug else "-O", "ENABLE_USER_SCRIPT_SANDBOXING": "NO",
        "ENABLE_TESTABILITY": "YES" if debug else "NO", "SWIFT_ACTIVE_COMPILATION_CONDITIONS": "DEBUG" if debug else "",
    }
    project_configs.append(add("project-config:" + name, f"isa = XCBuildConfiguration; buildSettings = {settings(common)}; name = {name};"))
    target_values = {
        "PRODUCT_NAME": "GPS", "PRODUCT_MODULE_NAME": "GPS", "MARKETING_VERSION": "0.3.0", "CURRENT_PROJECT_VERSION": "10",
        "TARGETED_DEVICE_FAMILY": "1", "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator", "SUPPORTS_MACCATALYST": "NO",
        "GENERATE_INFOPLIST_FILE": "NO", "INFOPLIST_FILE": "Config/Info.plist",
        "SWIFT_OBJC_BRIDGING_HEADER": "App/GPS-Bridging-Header.h", "HEADER_SEARCH_PATHS": "$(inherited) $(SRCROOT)/Native/include",
        "LIBRARY_SEARCH_PATHS": "$(inherited) $(SRCROOT)/Native/build/$(PLATFORM_NAME)",
        "OTHER_LDFLAGS": "$(inherited) -lgpsnative -lc++ -framework Security -framework SystemConfiguration",
        "LD_RUNPATH_SEARCH_PATHS": "$(inherited) @executable_path/Frameworks", "SWIFT_EMIT_LOC_STRINGS": "NO",
    }
    if assets.exists(): target_values["ASSETCATALOG_COMPILER_APPICON_NAME"] = "AppIcon"
    target_configs.append(add("target-config:" + name, f'isa = XCBuildConfiguration; baseConfigurationReference = {identifier("Config/Signing.xcconfig")}; buildSettings = {settings(target_values)}; name = {name};'))
project_list = add("project-config-list", f"isa = XCConfigurationList; buildConfigurations = {array(project_configs)}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;")
target_list = add("target-config-list", f"isa = XCConfigurationList; buildConfigurations = {array(target_configs)}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;")
target = add("target", f'isa = PBXNativeTarget; buildConfigurationList = {target_list}; buildPhases = {array([native, sources, frameworks, resources])}; buildRules = (); dependencies = (); packageProductDependencies = {array([signing_product])}; name = GPS; productName = GPS; productReference = {product}; productType = "com.apple.product-type.application";')
project = add("project", f'isa = PBXProject; attributes = {{ BuildIndependentTargetsInParallel = YES; LastUpgradeCheck = 2700; }}; buildConfigurationList = {project_list}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base,); mainGroup = {group}; productRefGroup = {products}; packageReferences = {array([signing_package])}; projectDirPath = ""; projectRoot = ""; targets = {array([target])};')
body = "// !$*UTF8*$!\n{\n archiveVersion = 1;\n classes = {};\n objectVersion = 56;\n objects = {\n"
body += "".join(f"  {key} = {{ {value} }};\n" for key, value in objects.items())
body += f" }};\n rootObject = {project};\n}}\n"
project_dir = ROOT / "GPS.xcodeproj"
write_generated(project_dir / "project.pbxproj", body)
scheme_dir = project_dir / "xcshareddata/xcschemes"
reference = f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{target}" BuildableName="GPS.app" BlueprintName="GPS" ReferencedContainer="container:GPS.xcodeproj"/>'
write_generated(scheme_dir / "GPS.xcscheme", f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
  <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{reference}</BuildActionEntry></BuildActionEntries></BuildAction>
  <TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables/></TestAction>
  <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="NO"><BuildableProductRunnable runnableDebuggingMode="0">{reference}</BuildableProductRunnable></LaunchAction>
  <ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">{reference}</BuildableProductRunnable></ProfileAction>
  <AnalyzeAction buildConfiguration="Debug"/>
  <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
if stale_paths:
    for path in stale_paths:
        print(f"Stale generated file: {path}")
    raise SystemExit(1)
print("Checked" if args.check else "Generated", "GPS.xcodeproj with", len(source_builds), "Swift sources")
