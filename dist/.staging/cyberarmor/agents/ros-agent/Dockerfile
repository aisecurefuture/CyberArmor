FROM ros:humble-ros-base

LABEL maintainer="AIShields Security Team <security@aishields.ai>"
LABEL description="AIShields Protect ROS2 Security Agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir requests pyyaml

WORKDIR /ros2_ws/src/aishields_ros_agent

COPY . .

WORKDIR /ros2_ws

RUN . /opt/ros/humble/setup.sh && \
    colcon build --packages-select aishields_ros_agent

COPY agents/ros-agent/entrypoint.sh /entrypoint.sh
RUN echo '#!/bin/bash\nset -e\nsource /opt/ros/humble/setup.bash\nsource /ros2_ws/install/setup.bash\nexec "$@"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["ros2", "run", "aishields_ros_agent", "aishields_node"]
