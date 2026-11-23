# ClickHouse Java Components
#
# Ranger agent jar build (Maven-based).
# Requires: mvn, JDK 11+
# The jar is part of the ClickHouse distribution; whether Ranger is used
# at runtime is controlled by config.xml (ranger.enabled=true/false).

find_program(MVN_EXECUTABLE mvn)

if(MVN_EXECUTABLE)
    # Ranger version: change via -DRANGER_VERSION=2.9.0
    set(RANGER_VERSION "2.5.0" CACHE STRING "Apache Ranger version for clickhouse-ranger-agent")

    set(JAVA_AGENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/clickhouse-ranger-agent")
    set(RANGER_AGENT_JAR "${JAVA_AGENT_DIR}/target/clickhouse-ranger-agent-0.1.0-SNAPSHOT.jar")

    # Build the Ranger agent jar (incremental: Maven handles staleness)
    # Included in default build since the jar is part of ClickHouse distribution
    add_custom_target(ranger-agent-jar ALL
        COMMAND ${MVN_EXECUTABLE} -q package -DskipTests -Dranger.version=${RANGER_VERSION}
        WORKING_DIRECTORY "${JAVA_AGENT_DIR}"
        COMMENT "Building Ranger agent (Ranger ${RANGER_VERSION})"
    )

    message(STATUS "Java: Maven found, ranger-agent-jar will be built with ClickHouse (Ranger ${RANGER_VERSION})")
else()
    message(WARNING "Java: Maven not found - Ranger agent jar will not be built. Install Maven to enable Ranger integration.")
endif()
