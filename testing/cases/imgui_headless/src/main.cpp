#include "imgui.h"

#include <iostream>

int main() {
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGui::StyleColorsDark();
  ImGuiIO &io = ImGui::GetIO();
  io.DisplaySize = ImVec2(320.0f, 180.0f);
  unsigned char *pixels = nullptr;
  int width = 0;
  int height = 0;
  io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
  ImGui::NewFrame();
  bool clicked = false;
  std::cout << "imgui:" << ImGui::GetFrameCount() << ":" << ImGui::GetVersion() << "\n";
  ImGui::DestroyContext();
  return clicked ? 1 : 0;
}
