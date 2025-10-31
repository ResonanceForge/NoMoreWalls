import re



config_file_meta = open("list.meta.yml")
content_lines = config_file_meta.readlines()

config_file_meta_autochoose = open("list.meta.autochoose.yml","w")


locations = ["- name: 🇯🇵 日本",
             "- name: 🇺🇸 美国",
             "- name: 🇭🇰 香港",
             "- name: 🇨🇳 台湾",
             "- name: 🇸🇬 新加坡",
             "- name: 🇨🇦 加拿大",
             "- name: 🇫🇷 法国",
             "- name: 🇬🇧 英国",
             "- name: 🇰🇷 韩国",
             "- name: 🇩🇪 德国",
             "- name: 🇨🇳 中国",
             "- name: 🇷🇺 俄罗斯",]

found_location=False
for location in locations:
    print(location)
    for i, line in enumerate(content_lines):
        # print(line)
        if location in line:
            found_location = True
            print("found \"location\"")
            break

        if found_location and "select" in line:
            print("found \"select\"")
            content_lines[i] = line.replace("select","url-test")
            print(content_lines)
            continue

config_file_meta_autochoose.writelines(content_lines)


config_file_meta.close()
config_file_meta_autochoose.close()
