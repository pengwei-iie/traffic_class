with open('words.txt', 'r', encoding='utf-8') as file_a, open('vocab.txt', 'r', encoding='utf-8') as file_b, open('new_vocab.txt', 'w', encoding='utf-8') as file_c:
    b_lines = set(line.strip() for line in file_b)
    for line in file_a:
        if line.strip() not in b_lines:
            file_c.write(line)
