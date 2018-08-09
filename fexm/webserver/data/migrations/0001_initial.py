# Generated by Django 2.0.1 on 2018-06-25 16:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Binary',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('path', models.CharField(max_length=500)),
                ('afl_dir', models.CharField(max_length=500)),
            ],
        ),
        migrations.CreateModel(
            name='Crash',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default=None, max_length=100, null=True)),
                ('parameter', models.CharField(max_length=500)),
                ('exploitability', models.CharField(max_length=500)),
                ('description', models.CharField(default=None, max_length=5000, null=True)),
                ('file_blob', models.BinaryField(default=None)),
                ('binary', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='data.Binary')),
            ],
        ),
        migrations.CreateModel(
            name='Package',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=500)),
                ('version', models.CharField(max_length=500)),
            ],
        ),
        migrations.AddField(
            model_name='binary',
            name='package',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='data.Package'),
        ),
    ]
