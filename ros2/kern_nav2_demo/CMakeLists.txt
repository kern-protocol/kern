cmake_minimum_required(VERSION 3.8)
project(kern_nav2_demo)

find_package(ament_cmake REQUIRED)

install(
  DIRECTORY launch worlds params maps rviz
  DESTINATION share/${PROJECT_NAME}
)

ament_package()
