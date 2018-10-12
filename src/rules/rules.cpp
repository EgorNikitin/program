//
// Created by root on 12.10.18.
//

#include <vector>
#include <string>
#include <fstream>
#include <iostream>

#define PROJECT_SOURCE_DIR "/home/univ/CLionProjects/program"

using namespace std;

vector<string> readFileRules() {
    vector<string> arr;
    ifstream file(PROJECT_SOURCE_DIR"/rules/rules.csv");
    string temp;

    while(getline(file, temp)){
        arr.push_back(temp);
    }

    /*for (int i = 0; i < arr.size(); ++i) {
        cout << i << " " << arr[i] << endl;
    }*/

    file.close();
    return arr;
}

