from os import walk

import collections
import math
import time

class DetectionMonitor:
    def __init__(self):
        self.detections = []

    def add_detection(self):
        detection_count = 0

        if len(self.detections) >= 60:
            self.detections.pop(0)
        self.detections.append(time.time())

        cur_time = time.time()
        threshold_time = cur_time-60

        for t in self.detections[::-1]:
            if t >= threshold_time:
                detection_count += 1

        if detection_count >= 5:
            print("RANSOMWARE")
            exit(0)

class File:
    def __init__(self, file_name, entropy):
        self.file_name = file_name
        self.current_entropy = entropy
        self.previous_entropy = entropy

    def add_entropy_value(self, entropy):
        self.previous_entropy = self.current_entropy
        self.current_entropy = entropy

    def get_entropy_difference(self):
        return self.current_entropy - self.previous_entropy

class FileEntropyDb:
    def __init__(self):
        self.file_lookup_table = {}

    def calc_entropy(self, file_str):
        file_str_len = len(file_str)
        char_array = []
        for char in file_str:
            char_array.append(char)

        counted_elements = collections.Counter(char_array)
        entropy = 0

        for el in counted_elements:
            el_count = counted_elements[el]
            ratio = el_count / float(file_str_len)
            entropy_i = ratio * (math.log(ratio, 2))
            entropy = entropy + entropy_i

        return entropy * -1

    def get_file_entropy(self, file_name):
        with open(file_name, "rb+") as file_handle:
            file_content = file_handle.read()
            return self.calc_entropy(file_content)
        return None

    def scan_file_system(self):
        dm = DetectionMonitor()
        while True:
            for (_, _, file_list) in walk("."):
                for file_name in file_list:
                    entropy_value = self.get_file_entropy(file_name)
                    if not entropy_value:
                        raise Exception(f"There was an error getting the entropy of {file_name}")
                    if file_name not in self.file_lookup_table:
                        self.file_lookup_table[file_name] = File(file_name, entropy_value)
                    self.file_lookup_table[file_name].add_entropy_value(entropy_value)

                    entropy_diff = self.file_lookup_table[file_name].get_entropy_difference()

                    if entropy_diff > 1.0:
                        dm.add_detection()

            time.sleep(2)



def main():
    file_db = FileEntropyDb()
    file_db.scan_file_system()


if __name__ == "__main__":
    main()
