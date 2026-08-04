"""Shared vocabulary for how a dependency's installed version was established.

Three of the advertised ecosystems declare versions somewhere other than the
manifest being scanned: Maven's ``<dependencyManagement>`` and imported BOMs
(#128), NuGet's ``Directory.Packages.props`` — Central Package Management —
(#129), and Gradle's ``gradle/libs.versions.toml`` version catalog (#101). Each
resolver records which of those answered, and the constants live here rather
than inside one ecosystem's parser so the next one reuses the vocabulary instead
of inventing a fourth spelling for the same idea (#131).

Gradle is the case that proves the arrangement was worth making. #164 held the
adapter back until the concept existed in two ecosystems, precisely so the third
would consume this vocabulary rather than become a third one-off; when it landed
it added one constant below and reused ``VERSION_SOURCE_KEY``,
``VERSION_SOURCE_DECLARED`` and ``VERSION_SOURCE_UNMANAGED`` verbatim, with no
Gradle-specific spelling of "unresolved" anywhere in ``parsers/gradle.py``.

:data:`VERSION_SOURCE_UNMANAGED` is the load-bearing one. It means the version
is declared somewhere this scan could not reach, which is a different fact from
"this project pins nothing" and very different from "the version is empty". The
formatter renders it as ``unmanaged → 2.22.1`` and the scorer drops the
version-drift signal from both the numerator and the denominator (#74) rather
than scoring a fabricated zero.
"""

# Key under which the source is recorded in ``DependencyMetadata.additional_info``.
VERSION_SOURCE_KEY = "version_source"

# The manifest being scanned states the version itself.
VERSION_SOURCE_DECLARED = "declared"

# Maven: resolved through the effective <dependencyManagement> — the project's
# own block, a parent POM in the chain, or an imported BOM.
VERSION_SOURCE_MANAGED = "dependency-management"

# NuGet: resolved from a Directory.Packages.props <PackageVersion> entry.
VERSION_SOURCE_CENTRAL = "central-package-management"

# NuGet: a VersionOverride on the PackageReference beat the central declaration.
VERSION_SOURCE_OVERRIDE = "version-override"

# Gradle: resolved from a gradle/libs.versions.toml version catalog, either
# straight off the ``[libraries]`` entry or through its ``version.ref`` into
# ``[versions]``.
VERSION_SOURCE_CATALOG = "version-catalog"

# Declared somewhere unreachable, or in a form that does not name one concrete
# version (a floating "1.2.*", an open-ended range). Honestly unmeasured.
VERSION_SOURCE_UNMANAGED = "unmanaged"
