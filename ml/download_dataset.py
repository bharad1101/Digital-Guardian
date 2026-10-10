import os
import io
import zipfile
import urllib.request
import pandas as pd


URL = (
    "https://archive.ics.uci.edu/static/"
    "public/228/sms+spam+collection.zip"
)

OUTPUT_FILE = "data/sms_spam_dataset.csv"


print("\n======================================")
print(" DIGITAL GUARDIAN DATASET DOWNLOADER")
print("======================================")

print("\nDownloading SMS Spam Collection...")


try:

    response = urllib.request.urlopen(
        URL,
        timeout=30
    )

    zip_data = response.read()

    print("Download completed.")


    with zipfile.ZipFile(
        io.BytesIO(zip_data)
    ) as zip_file:

        print("\nFiles inside dataset:")

        for file_name in zip_file.namelist():
            print("-", file_name)


        with zip_file.open(
            "SMSSpamCollection"
        ) as dataset_file:

            df = pd.read_csv(
                dataset_file,
                sep="\t",
                header=None,
                names=[
                    "label",
                    "message"
                ],
                encoding="utf-8"
            )


    # Clean dataset

    df = df.dropna()

    df["label"] = (
        df["label"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    df["message"] = (
        df["message"]
        .astype(str)
        .str.strip()
    )


    # Remove duplicates

    df = df.drop_duplicates()


    # Create data directory

    os.makedirs(
        "data",
        exist_ok=True
    )


    # Save cleaned CSV

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )


    print("\n======================================")
    print(" DATASET READY")
    print("======================================")

    print(
        "\nTotal samples:",
        len(df)
    )

    print(
        "\nClass distribution:"
    )

    print(
        df["label"].value_counts()
    )

    print(
        "\nDataset saved to:"
    )

    print(
        OUTPUT_FILE
    )


except Exception as error:

    print(
        "\nDataset download failed:"
    )

    print(
        error
    )
