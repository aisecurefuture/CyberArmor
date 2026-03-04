from setuptools import setup, find_packages

package_name = "aishields_ros_agent"

setup(
    name=package_name,
    version="1.0.0",
    packages=find_packages(),
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        ("share/" + package_name, ["package.xml"]),
    ],
    install_requires=["setuptools", "pyyaml", "requests"],
    zip_safe=True,
    maintainer="AIShields Security Team",
    maintainer_email="security@aishields.ai",
    description="AIShields Protect security agent for ROS2 robotic systems",
    license="Proprietary",
    entry_points={
        "console_scripts": [
            "aishields_node = aishields_ros_node:main",
        ],
    },
)
